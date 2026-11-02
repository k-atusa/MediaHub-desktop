package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/k-atusa/USAG-Lib/Bencode"
	"github.com/k-atusa/USAG-Lib/Bencrypt"
	"github.com/k-atusa/USAG-Lib/Opsec"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// Client coordinates MediaHub API communication and encryption
type Client struct {
	server     string
	safeTLS    bool
	httpClient *http.Client
	uHash      string
	uKey       []byte
	username   string
	fldMap     map[string][]byte
	mu         sync.RWMutex
}

// Construct new MediaHub client instance
func newClient(server string, safeTLS bool) *Client {
	return &Client{
		server:     strings.TrimRight(server, "/"),
		safeTLS:    safeTLS,
		httpClient: newHTTPClient(safeTLS),
		fldMap:     make(map[string][]byte),
	}
}

// Authenticate user with password derivation via Argon2id
func (c *Client) auth(user, pw string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Derive master key using Argon2id
	salt := Bencrypt.SHA3256([]byte(user + SecretPepper))
	pwBytes := Bencode.NormPW(pw)

	hm := new(Bencrypt.HashMaster)
	if err := hm.Init("arg2st", 0, 0); err != nil {
		return fmt.Errorf("KDF init failed: %w", err)
	}

	stKey, uKey, err := hm.KDF(pwBytes, salt)
	if err != nil {
		return fmt.Errorf("KDF derivation failed: %w", err)
	}

	// Update authentication state
	c.uHash = usrPid(stKey)
	c.uKey = uKey
	c.username = user
	c.fldMap = make(map[string][]byte)
	return nil
}

// Restore client authentication credentials from session
func (c *Client) setAuth(uHash string, uKey []byte, user string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.uHash = uHash
	c.uKey = uKey
	c.username = user
	c.fldMap = make(map[string][]byte)
}

// Clear client authentication credentials
func (c *Client) clearAuth() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.uHash = ""
	c.uKey = nil
	c.username = ""
	c.fldMap = make(map[string][]byte)
}

// Get active authentication credentials
func (c *Client) getAuthInfo() (string, []byte, string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.uHash, c.uKey, c.username
}

// Check if user account exists on server
func (c *Client) checkUserExists(uHash string) (bool, error) {
	urlStr := fmt.Sprintf("%s/api/userdata/%s", c.server, uHash)
	res, err := c.httpClient.Get(urlStr)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()
	return res.StatusCode != http.StatusNotFound, nil
}

// Register user account on server with optional invite code
func (c *Client) registerUser(uHash, inviteCode string) error {
	urlStr := fmt.Sprintf("%s/api/userdata/%s", c.server, uHash)
	req, err := http.NewRequest(http.MethodPost, urlStr, bytes.NewReader([]byte{}))
	if err != nil {
		return err
	}
	if inviteCode != "" {
		req.Header.Set("X-Invite-Code", inviteCode)
	}

	res, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		if res.StatusCode == http.StatusForbidden {
			return errors.New("Invalid invite code")
		}
		return fmt.Errorf("Registration failed (HTTP %d)", res.StatusCode)
	}
	return nil
}

// Delete user account data on server
func (c *Client) deleteUserData(uHash string) error {
	urlStr := fmt.Sprintf("%s/api/userdata/%s", c.server, uHash)
	req, err := http.NewRequest(http.MethodDelete, urlStr, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-User-Hash", uHash)

	res, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusNotFound {
		return fmt.Errorf("Failed to delete user data (HTTP %d)", res.StatusCode)
	}
	return nil
}

// Fetch and decrypt folder map from server
func (c *Client) getFlds() (map[string][]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.uHash == "" || len(c.uKey) < 32 {
		return nil, errors.New("Not authenticated")
	}

	// Request encrypted userdata
	urlStr := fmt.Sprintf("%s/api/userdata/%s", c.server, c.uHash)
	res, err := c.httpClient.Get(urlStr)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusNotFound {
		c.fldMap = make(map[string][]byte)
		return c.fldMap, nil
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Connection error: code %d", res.StatusCode)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if len(body) == 0 {
		c.fldMap = make(map[string][]byte)
		return c.fldMap, nil
	}

	// Decrypt userdata binary
	sm := new(Bencrypt.SymMaster)
	if err := sm.Init("gcm1", c.uKey[:32]); err != nil {
		return nil, err
	}

	dec, err := sm.DeBin(body)
	if err != nil {
		return nil, fmt.Errorf("Failed to decrypt userdata: %w", err)
	}

	c.fldMap = Opsec.DecodeCfg(dec)
	return c.fldMap, nil
}

// Encrypt and persist folder map to server
func (c *Client) saveFlds(targetHash, oldHash string) error {
	c.mu.RLock()
	fMap := c.fldMap
	uKey := c.uKey
	uHash := c.uHash
	server := c.server
	c.mu.RUnlock()

	if uHash == "" || len(uKey) < 32 {
		return errors.New("Not authenticated")
	}

	if targetHash == "" {
		targetHash = uHash
	}

	// Serialize and encrypt folder map
	bin, err := Opsec.EncodeCfg(fMap)
	if err != nil {
		return err
	}

	sm := new(Bencrypt.SymMaster)
	if err := sm.Init("gcm1", uKey[:32]); err != nil {
		return err
	}

	enc, err := sm.EnBin(bin)
	if err != nil {
		return err
	}

	// Post encrypted payload to server
	urlStr := fmt.Sprintf("%s/api/userdata/%s", server, targetHash)
	req, err := http.NewRequest(http.MethodPost, urlStr, bytes.NewReader(enc))
	if err != nil {
		return err
	}

	userHashHdr := oldHash
	if userHashHdr == "" {
		userHashHdr = targetHash
	}
	req.Header.Set("X-User-Hash", userHashHdr)
	if oldHash != "" {
		req.Header.Set("X-Old-Hash", oldHash)
	}

	res, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("Failed to save userdata: code %d", res.StatusCode)
	}
	return nil
}

// Create new folder entry and sync to server
func (c *Client) mkFld(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("Folder name cannot be empty")
	}

	c.mu.Lock()
	if _, exists := c.fldMap[name]; exists {
		c.mu.Unlock()
		return errors.New("Folder name already exists!")
	}
	randKey := append(Bencrypt.Random(32), Bencrypt.Random(12)...)
	c.fldMap[name] = randKey
	c.mu.Unlock()

	return c.saveFlds("", "")
}

// Rename folder entry and persist changes
func (c *Client) renameFld(oldName, newName string) error {
	oldName = strings.TrimSpace(oldName)
	newName = strings.TrimSpace(newName)
	if oldName == "" || newName == "" {
		return errors.New("Folder name cannot be empty")
	}
	if oldName == newName {
		return nil
	}

	c.mu.Lock()
	key, exists := c.fldMap[oldName]
	if !exists {
		c.mu.Unlock()
		return fmt.Errorf("Folder '%s' not found", oldName)
	}
	if _, duplicate := c.fldMap[newName]; duplicate {
		c.mu.Unlock()
		return fmt.Errorf("Folder '%s' already exists", newName)
	}

	c.fldMap[newName] = key
	delete(c.fldMap, oldName)
	c.mu.Unlock()

	if err := c.saveFlds("", ""); err != nil {
		// Rollback map mutation on failure
		c.mu.Lock()
		c.fldMap[oldName] = key
		delete(c.fldMap, newName)
		c.mu.Unlock()
		return err
	}
	return nil
}

// Delete folder entry and remote folder metadata
func (c *Client) delFld(name string) error {
	name = strings.TrimSpace(name)
	c.mu.Lock()
	fKey, exists := c.fldMap[name]
	if !exists {
		c.mu.Unlock()
		return nil
	}
	fPid := objPid(fKey)
	delete(c.fldMap, name)
	uHash := c.uHash
	server := c.server
	c.mu.Unlock()

	// Delete folder metadata from server
	urlStr := fmt.Sprintf("%s/api/storage/%s/names", server, fPid)
	req, err := http.NewRequest(http.MethodDelete, urlStr, nil)
	if err == nil {
		req.Header.Set("X-User-Hash", uHash)
		if res, err := c.httpClient.Do(req); err == nil {
			res.Body.Close()
		}
	}

	return c.saveFlds("", "")
}

// Trim orphan files from folder on remote server
func (c *Client) trimFld(folderName string, activePids []string) (string, error) {
	c.mu.RLock()
	fKey, exists := c.fldMap[folderName]
	uHash := c.uHash
	server := c.server
	c.mu.RUnlock()

	if !exists {
		return "", fmt.Errorf("Folder '%s' not found", folderName)
	}

	fPid := objPid(fKey)
	payload, _ := json.Marshal(map[string]interface{}{"pids": activePids})

	urlStr := fmt.Sprintf("%s/api/trim/%s", server, fPid)
	req, err := http.NewRequest(http.MethodPost, urlStr, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User-Hash", uHash)

	res, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Trim failed (HTTP %d)", res.StatusCode)
	}
	return string(body), nil
}

// Resolve folder ID and key by folder name or folder PID
func (c *Client) resolveFolder(folderIdOrName string) (string, []byte, error) {
	c.mu.RLock()
	// Direct folder name match
	if fKey, exists := c.fldMap[folderIdOrName]; exists {
		c.mu.RUnlock()
		return objPid(fKey), fKey, nil
	}

	// PID match against cached folders
	for _, fKey := range c.fldMap {
		if objPid(fKey) == folderIdOrName {
			c.mu.RUnlock()
			return folderIdOrName, fKey, nil
		}
	}
	c.mu.RUnlock()

	// Try reloading folders from server if not found in cache
	if _, err := c.getFlds(); err == nil {
		c.mu.RLock()
		defer c.mu.RUnlock()
		if fKey, exists := c.fldMap[folderIdOrName]; exists {
			return objPid(fKey), fKey, nil
		}
		for _, fKey := range c.fldMap {
			if objPid(fKey) == folderIdOrName {
				return folderIdOrName, fKey, nil
			}
		}
	}

	return "", nil, fmt.Errorf("Folder '%s' not found", folderIdOrName)
}

// Fetch and decrypt folder file map from server by folder name or PID
func (c *Client) getFiles(folderIdOrName string) (string, []byte, map[string][]byte, error) {
	fPid, fKey, err := c.resolveFolder(folderIdOrName)
	if err != nil {
		return "", nil, nil, err
	}

	c.mu.RLock()
	server := c.server
	c.mu.RUnlock()

	urlStr := fmt.Sprintf("%s/api/storage/%s/names", server, fPid)
	res, err := c.httpClient.Get(urlStr)
	if err != nil {
		return fPid, fKey, nil, err
	}
	defer res.Body.Close()

	flMap := make(map[string][]byte)
	if res.StatusCode == http.StatusNotFound {
		return fPid, fKey, flMap, nil
	}
	if res.StatusCode != http.StatusOK {
		return fPid, fKey, nil, fmt.Errorf("Failed to load folder meta: code %d", res.StatusCode)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return fPid, fKey, nil, err
	}

	if len(body) > 0 {
		// Decrypt file map binary
		sm := new(Bencrypt.SymMaster)
		if err := sm.Init("gcm1", fKey[:32]); err != nil {
			return fPid, fKey, nil, err
		}
		dec, err := sm.DeBin(body)
		if err != nil {
			return fPid, fKey, nil, fmt.Errorf("Failed to decrypt folder meta: %w", err)
		}
		flMap = Opsec.DecodeCfg(dec)
	}

	return fPid, fKey, flMap, nil
}

// Encrypt and persist file map to server
func (c *Client) saveFiles(fldPid string, fKey []byte, flMap map[string][]byte) error {
	c.mu.RLock()
	uHash := c.uHash
	server := c.server
	c.mu.RUnlock()

	// Serialize and encrypt file map
	bin, err := Opsec.EncodeCfg(flMap)
	if err != nil {
		return err
	}

	sm := new(Bencrypt.SymMaster)
	if err := sm.Init("gcm1", fKey[:32]); err != nil {
		return err
	}

	enc, err := sm.EnBin(bin)
	if err != nil {
		return err
	}

	// Send encrypted map to storage endpoint
	urlStr := fmt.Sprintf("%s/api/storage/%s/names", server, fldPid)
	req, err := http.NewRequest(http.MethodPost, urlStr, bytes.NewReader(enc))
	if err != nil {
		return err
	}
	if uHash != "" {
		req.Header.Set("X-User-Hash", uHash)
	}

	res, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("Failed to save folder map (HTTP %d)", res.StatusCode)
	}
	return nil
}

// Rename file entry in folder and sync metadata
func (c *Client) renameFile(folderName, oldName, newName string) error {
	fPid, fKey, flMap, err := c.getFiles(folderName)
	if err != nil {
		return err
	}

	oldName = strings.TrimSpace(oldName)
	newName = strings.TrimSpace(newName)
	if oldName == "" || newName == "" {
		return errors.New("File name cannot be empty")
	}
	if oldName == newName {
		return nil
	}

	flInfo, exists := flMap[oldName]
	if !exists {
		return fmt.Errorf("File '%s' not found", oldName)
	}
	if _, duplicate := flMap[newName]; duplicate {
		return fmt.Errorf("File '%s' already exists", newName)
	}

	flMap[newName] = flInfo
	delete(flMap, oldName)

	return c.saveFiles(fPid, fKey, flMap)
}

// Delete file binary and thumbnail from server
func (c *Client) deleteFile(folderName, fileName string) error {
	fPid, fKey, flMap, err := c.getFiles(folderName)
	if err != nil {
		return err
	}

	flInfo, exists := flMap[fileName]
	if !exists {
		return nil
	}

	c.mu.RLock()
	uHash := c.uHash
	server := c.server
	c.mu.RUnlock()

	fk := flInfo[:44]
	fpid := objPid(fk)

	// Delete data binary from server
	delDatUrl := fmt.Sprintf("%s/api/media/%s/%s/dat", server, fPid, fpid)
	if res, err := c.httpClient.Do(newDeleteReq(delDatUrl, uHash)); err == nil {
		res.Body.Close()
	}

	// Delete thumbnail from server
	delThumbUrl := fmt.Sprintf("%s/api/media/%s/%s/thumb", server, fPid, fpid)
	if res, err := c.httpClient.Do(newDeleteReq(delThumbUrl, uHash)); err == nil {
		res.Body.Close()
	}

	delete(flMap, fileName)
	return c.saveFiles(fPid, fKey, flMap)
}

// Export password-protected folder share token
func (c *Client) exportShareToken(folderName, password string) (string, error) {
	c.mu.RLock()
	fKey, exists := c.fldMap[folderName]
	c.mu.RUnlock()

	if !exists {
		return "", fmt.Errorf("Folder '%s' not found", folderName)
	}
	if password == "" {
		return "", errors.New("Password required")
	}

	// Encrypt share packet with password
	op := new(Opsec.Opsec)
	op.Init()
	op.Smsg = folderName
	op.SmsgInfo = fKey

	pwBytes := Bencode.NormPW(password)
	head, err := op.Encpw("arg2st", pwBytes, nil)
	if err != nil {
		return "", err
	}

	return Bencode.Encode64(head, "#", 40, 10)
}

// Import password-protected folder share token
func (c *Client) importShareToken(tokenText, password string) (string, []byte, error) {
	if tokenText == "" || password == "" {
		return "", nil, errors.New("Token and password required")
	}

	// Decode and decrypt share packet
	raw, err := Bencode.Decode64(strings.TrimSpace(tokenText), "#")
	if err != nil {
		return "", nil, fmt.Errorf("Invalid token format: %w", err)
	}

	op := new(Opsec.Opsec)
	op.Init()
	op.View(raw)

	pwBytes := Bencode.NormPW(password)
	if err := op.Decpw(pwBytes, nil); err != nil {
		return "", nil, fmt.Errorf("Decryption failed: %w", err)
	}

	if op.Smsg == "" || len(op.SmsgInfo) < 44 {
		return "", nil, errors.New("Invalid share token payload")
	}

	// Store imported folder key
	c.mu.Lock()
	c.fldMap[op.Smsg] = op.SmsgInfo
	c.mu.Unlock()

	if err := c.saveFlds("", ""); err != nil {
		return "", nil, err
	}

	return op.Smsg, op.SmsgInfo, nil
}

// Change account password and re-encrypt userdata
func (c *Client) changePassword(newPw string) error {
	c.mu.Lock()
	username := c.username
	oldHash := c.uHash
	fMap := c.fldMap
	c.mu.Unlock()

	if username == "" || oldHash == "" {
		return errors.New("Not authenticated")
	}

	// Derive new master key
	salt := Bencrypt.SHA3256([]byte(username + SecretPepper))
	pwBytes := Bencode.NormPW(newPw)

	hm := new(Bencrypt.HashMaster)
	if err := hm.Init("arg2st", 0, 0); err != nil {
		return err
	}
	stKey, newUKey, err := hm.KDF(pwBytes, salt)
	if err != nil {
		return err
	}
	newHash := usrPid(stKey)

	if newHash == oldHash {
		return errors.New("New password must be different")
	}

	// Ensure target hash does not exist
	exists, err := c.checkUserExists(newHash)
	if err != nil {
		return err
	}
	if exists {
		return errors.New("User already exists with this password")
	}

	// Re-encrypt folder map with new key
	bin, err := Opsec.EncodeCfg(fMap)
	if err != nil {
		return err
	}

	sm := new(Bencrypt.SymMaster)
	if err := sm.Init("gcm1", newUKey[:32]); err != nil {
		return err
	}

	enc, err := sm.EnBin(bin)
	if err != nil {
		return err
	}

	// Post under new user hash
	urlStr := fmt.Sprintf("%s/api/userdata/%s", c.server, newHash)
	req, err := http.NewRequest(http.MethodPost, urlStr, bytes.NewReader(enc))
	if err != nil {
		return err
	}
	req.Header.Set("X-User-Hash", oldHash)
	req.Header.Set("X-Old-Hash", oldHash)

	res, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("Failed to re-encrypt userdata: code %d", res.StatusCode)
	}

	// Purge old userdata
	_ = c.deleteUserData(oldHash)

	// Update active credentials
	c.mu.Lock()
	c.uHash = newHash
	c.uKey = newUKey
	c.mu.Unlock()

	return nil
}

// Upload file using temp disk buffer to avoid memory footprint
func (c *Client) uploadFileNamed(ctx context.Context, fldName, fileName, localPath string, thumbBytes []byte, isCanceled *atomic.Bool, progCb ProgressCallback) error {
	if c.uHash == "" {
		return errors.New("Not authenticated")
	}

	srcFile, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	stat, err := srcFile.Stat()
	if err != nil {
		return err
	}
	origSz := stat.Size()

	fPid, fKey, flMap, err := c.getFiles(fldName)
	if err != nil {
		return err
	}

	// Delete old duplicate file if present
	if oldInfo, exists := flMap[fileName]; exists && len(oldInfo) >= 44 {
		oldPid := objPid(oldInfo[:44])
		if res, err := c.httpClient.Do(newDeleteReq(fmt.Sprintf("%s/api/media/%s/%s/dat", c.server, fPid, oldPid), c.uHash)); err == nil {
			res.Body.Close()
		}
		if res, err := c.httpClient.Do(newDeleteReq(fmt.Sprintf("%s/api/media/%s/%s/thumb", c.server, fPid, oldPid), c.uHash)); err == nil {
			res.Body.Close()
		}
	}

	// Generate new random file key
	fk := append(Bencrypt.Random(32), Bencrypt.Random(12)...)
	fpid := objPid(fk)

	// Upload webview-generated thumbnail if provided
	if len(thumbBytes) > 0 {
		sm := new(Bencrypt.SymMaster)
		if err := sm.Init("gcm1", fk[:32]); err == nil {
			if encThumb, err := sm.EnBin(thumbBytes); err == nil {
				thumbUrl := fmt.Sprintf("%s/api/media/%s/%s/thumb", c.server, fPid, fpid)
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, thumbUrl, bytes.NewReader(encThumb))
				if err == nil {
					req.Header.Set("X-User-Hash", c.uHash)
					if res, err := c.httpClient.Do(req); err == nil {
						res.Body.Close()
					}
				}
			}
		}
	}

	if isCanceled != nil && isCanceled.Load() {
		return errors.New("UPLOAD_CANCELLED")
	}

	// Create temp file in temp directory for streaming cipher
	_ = os.MkdirAll("./temp", 0755)
	tmpFile, err := os.CreateTemp("./temp", "mh-up-*.tmp")
	if err != nil {
		return fmt.Errorf("Failed to create temp file: %w", err)
	}
	tmpName := tmpFile.Name()
	defer func() {
		tmpFile.Close()
		_ = os.Remove(tmpName)
	}()

	smx := new(Bencrypt.SymMaster)
	if err := smx.Init("gcmx1", fk[:32]); err != nil {
		return err
	}

	encSz := smx.AfterSize(origSz)
	padSz := Opsec.PadLen(encSz)
	totSize := encSz + padSz

	// Stream encrypt directly from source to temp file
	if err := smx.EnFile(srcFile, origSz, tmpFile); err != nil {
		return fmt.Errorf("Stream encryption failed: %w", err)
	}

	// Append padding directly to temp file
	if padSz > 0 {
		if err := Opsec.PadFile(tmpFile, padSz); err != nil {
			return fmt.Errorf("Padding failed: %w", err)
		}
	}

	if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
		return err
	}

	if isCanceled != nil && isCanceled.Load() {
		return errors.New("UPLOAD_CANCELLED")
	}

	// Upload ciphertext in 2MB chunks from temp file
	offset := int64(0)
	t0 := time.Now()
	wb := int64(0)

	if totSize == 0 {
		datUrl := fmt.Sprintf("%s/api/media/%s/%s/dat", c.server, fPid, fpid)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, datUrl, bytes.NewReader([]byte{}))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Length", "0")
		req.Header.Set("X-Upload-Offset", "0")
		req.Header.Set("X-User-Hash", c.uHash)
		res, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			return fmt.Errorf("Upload failed (HTTP %d)", res.StatusCode)
		}
	} else {
		buf := make([]byte, TransferChunkSize)
		for offset < totSize {
			if isCanceled != nil && isCanceled.Load() {
				return errors.New("UPLOAD_CANCELLED")
			}

			readSize := int64(len(buf))
			if totSize-offset < readSize {
				readSize = totSize - offset
			}

			n, err := io.ReadFull(tmpFile, buf[:readSize])
			if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
				return err
			}
			if n == 0 {
				break
			}

			chunk := buf[:n]
			datUrl := fmt.Sprintf("%s/api/media/%s/%s/dat", c.server, fPid, fpid)

			// Retry chunk up to 3 times
			var lastErr error
			for attempt := 1; attempt <= 3; attempt++ {
				if isCanceled != nil && isCanceled.Load() {
					return errors.New("UPLOAD_CANCELLED")
				}

				req, err := http.NewRequestWithContext(ctx, http.MethodPost, datUrl, bytes.NewReader(chunk))
				if err != nil {
					lastErr = err
					continue
				}
				req.Header.Set("Content-Length", fmt.Sprintf("%d", n))
				req.Header.Set("X-Upload-Offset", fmt.Sprintf("%d", offset))
				req.Header.Set("X-User-Hash", c.uHash)

				res, err := c.httpClient.Do(req)
				if err != nil {
					lastErr = err
					time.Sleep(time.Duration(attempt*200) * time.Millisecond)
					continue
				}
				res.Body.Close()

				if res.StatusCode == http.StatusOK {
					lastErr = nil
					break
				}
				lastErr = fmt.Errorf("Upload failed (HTTP %d)", res.StatusCode)
				time.Sleep(time.Duration(attempt*200) * time.Millisecond)
			}

			if lastErr != nil {
				return lastErr
			}

			offset += int64(n)
			wb += int64(n)

			now := time.Now()
			el := now.Sub(t0).Seconds()
			if (el >= 0.1 || offset == totSize) && progCb != nil {
				progCb(offset, totSize, float64(wb)/max(el, 0.001))
				t0 = now
				wb = 0
			}
		}
	}

	if progCb != nil {
		progCb(totSize, totSize, 0)
	}

	// Update file map metadata on server
	flInfo := append(fk, Opsec.EncodeInt(uint64(origSz), 8)...)
	flMap[fileName] = flInfo

	return c.saveFiles(fPid, fKey, flMap)
}

// Download file directly to local destination without buffering in memory
func (c *Client) downloadFile(ctx context.Context, fldName, fileName, filePid, fileKeyHex string, destPath string, isCanceled *atomic.Bool, progCb ProgressCallback) error {
	var fPid, fpid string
	var fk []byte
	var origSz int64

	// If explicit file key and PID are provided, bypass metadata map lookup
	if filePid != "" && fileKeyHex != "" {
		resolvedPid, _, err := c.resolveFolder(fldName)
		if err == nil {
			fPid = resolvedPid
		} else {
			fPid = fldName
		}
		rawK, err := hex.DecodeString(fileKeyHex)
		if err == nil && len(rawK) >= 44 {
			fk = rawK[:44]
			fpid = filePid
			if len(rawK) >= 52 {
				origSz = int64(Opsec.DecodeInt(rawK[44:52]))
			}
		}
	}

	// Lookup via folder file map if not fully resolved
	if len(fk) < 32 || fPid == "" || fpid == "" {
		resolvedPid, _, flMap, err := c.getFiles(fldName)
		if err != nil {
			return err
		}
		fPid = resolvedPid

		flInfo, ok := flMap[fileName]
		if !ok || len(flInfo) < 52 {
			// Match by file PID against all files in folder
			for _, info := range flMap {
				if len(info) >= 44 && (objPid(info[:44]) == fileName || objPid(info[:44]) == filePid) {
					flInfo = info
					ok = true
					break
				}
			}
			if !ok || len(flInfo) < 52 {
				return fmt.Errorf("File '%s' not found", fileName)
			}
		}

		fk = flInfo[:44]
		origSz = int64(Opsec.DecodeInt(flInfo[44:52]))
		fpid = objPid(fk)
	}

	smx := new(Bencrypt.SymMaster)
	if err := smx.Init("gcmx1", fk[:32]); err != nil {
		return err
	}
	ciphSz := smx.AfterSize(origSz)

	// Stream decrypt directly from reader to destination file
	datUrl := fmt.Sprintf("%s/api/media/%s/%s/dat", c.server, fPid, fpid)
	reader := newChunkedRangeReader(datUrl, ciphSz, TransferChunkSize, c.httpClient, progCb, isCanceled)
	defer reader.Close()

	destFile, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer destFile.Close()

	if err := smx.DeFile(reader, ciphSz, destFile); err != nil {
		_ = os.Remove(destPath)
		return err
	}

	if progCb != nil {
		progCb(ciphSz, ciphSz, 0)
	}
	return nil
}

// UploadSession tracks an in-flight file upload streamed from webview
type UploadSession struct {
	folderName string
	fileName   string
	totalSize  int64
	fileIdx    int
	thumbBytes []byte
	tmpFile    *os.File
	tmpPath    string
}

// FileEntry represents a file in a folder
type FileEntry struct {
	Name    string `json:"name"`
	FilePid string `json:"filePid"`
	FileKey string `json:"fileKey"`
	RawInfo string `json:"rawInfo"`
	Size    int64  `json:"size"`
}

// FolderContents represents contents of a folder
type FolderContents struct {
	FolderId  string               `json:"folderId"`
	FolderKey string               `json:"folderKey"`
	Files     map[string]FileEntry `json:"files"`
}

// App coordinates desktop lifecycle and frontend bindings
type App struct {
	ctx            context.Context
	client         *Client
	proxy          *Proxy
	sessionFile    string
	uploadCancel   atomic.Bool
	downCancel     atomic.Bool
	currentFld     string
	currentFlMap   map[string][]byte
	mapMu          sync.RWMutex
	uploadSessions map[string]*UploadSession
	upMu           sync.Mutex
}

// NewApp creates a new App application struct
func NewApp() *App {
	initEnv()
	client := newClient(cfg.Server, cfg.SafeTLS)
	proxy := NewProxy(cfg.ProxyPort)

	return &App{
		client:         client,
		proxy:          proxy,
		sessionFile:    "./temp/session.vault",
		currentFlMap:   make(map[string][]byte),
		uploadSessions: make(map[string]*UploadSession),
	}
}

// Startup initializes Wails runtime and background proxy
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	if err := a.proxy.Start(a.client); err != nil {
		println("Failed to start streaming proxy:", err.Error())
	}
}

// Shutdown cleans up resources when application exits
func (a *App) shutdown(ctx context.Context) {
	if a.proxy != nil {
		a.proxy.Stop()
	}
}

// GetConfig returns the application configuration
func (a *App) GetConfig() map[string]interface{} {
	return map[string]interface{}{
		"server":    cfg.Server,
		"safetls":   cfg.SafeTLS,
		"proxyPort": a.proxy.GetPort(),
	}
}

// FetchNotice gets notice message from remote server
func (a *App) FetchNotice() string {
	urlStr := fmt.Sprintf("%s/api/notice", a.client.server)
	res, err := a.client.httpClient.Get(urlStr)
	if err != nil {
		return ""
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return ""
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return ""
	}

	var data struct {
		Notice string `json:"notice"`
	}
	_ = json.Unmarshal(body, &data)
	return data.Notice
}

// ShowAppInfo displays standard desktop info dialog
func (a *App) ShowAppInfo() {
	_, _ = runtime.MessageDialog(a.ctx, runtime.MessageDialogOptions{
		Type:    runtime.InfoDialog,
		Title:   "About MediaHub Desktop",
		Message: "MediaHub Desktop GE (Go + Wails)\nVersion 1.6.0\nZero-Knowledge E2EE Cloud Storage Desktop Client",
	})
}

// Login authenticates with username and password
func (a *App) Login(username, password string) (map[string]interface{}, error) {
	if err := a.client.auth(username, password); err != nil {
		return nil, err
	}

	uHash, uKey, _ := a.client.getAuthInfo()
	exists, err := a.client.checkUserExists(uHash)
	if err != nil {
		return nil, fmt.Errorf("Connection error: %w", err)
	}
	if !exists {
		return nil, errors.New("User does not exist")
	}

	// Preload folders and update proxy
	fldMap, err := a.client.getFlds()
	if err != nil {
		return nil, err
	}
	a.proxy.UpdateContext(a.client, nil)

	return map[string]interface{}{
		"userHash": uHash,
		"userKey":  hex.EncodeToString(uKey),
		"username": username,
		"fldCount": len(fldMap),
	}, nil
}

// Register creates a new user account
func (a *App) Register(username, password, inviteCode string) (map[string]interface{}, error) {
	if err := a.client.auth(username, password); err != nil {
		return nil, err
	}

	uHash, uKey, _ := a.client.getAuthInfo()
	exists, err := a.client.checkUserExists(uHash)
	if err != nil {
		return nil, fmt.Errorf("Connection error: %w", err)
	}
	if exists {
		return nil, errors.New("User already exists")
	}

	if err := a.client.registerUser(uHash, inviteCode); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"userHash": uHash,
		"userKey":  hex.EncodeToString(uKey),
		"username": username,
	}, nil
}

// CheckUserExists checks if username exists on server
func (a *App) CheckUserExists(username, password string) (bool, error) {
	tmpClient := newClient(a.client.server, a.client.safeTLS)
	if err := tmpClient.auth(username, password); err != nil {
		return false, err
	}
	uHash, _, _ := tmpClient.getAuthInfo()
	return a.client.checkUserExists(uHash)
}

// Logout clears active user session
func (a *App) Logout() {
	a.client.clearAuth()
	a.proxy.UpdateContext(nil, nil)
	a.mapMu.Lock()
	a.currentFld = ""
	a.currentFlMap = make(map[string][]byte)
	a.mapMu.Unlock()
	_ = a.ClearSessionBytes()
}

// SaveSessionBytes persists session bytes to desktop temp vault
func (a *App) SaveSessionBytes(hexStr string) error {
	_ = os.MkdirAll("./temp", 0755)
	return os.WriteFile(a.sessionFile, []byte(hexStr), 0600)
}

// LoadSessionBytes loads session bytes from desktop temp vault
func (a *App) LoadSessionBytes() (string, error) {
	if _, err := os.Stat(a.sessionFile); os.IsNotExist(err) {
		return "", nil
	}
	data, err := os.ReadFile(a.sessionFile)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ClearSessionBytes removes desktop temp vault
func (a *App) ClearSessionBytes() error {
	_ = os.Remove(a.sessionFile)
	return nil
}

// RestoreAuth restores auth state from userHash and hex-encoded userKey
func (a *App) RestoreAuth(uHash, uKeyHex, username string) error {
	uKey, err := hex.DecodeString(uKeyHex)
	if err != nil {
		return err
	}
	a.client.setAuth(uHash, uKey, username)
	return nil
}

// GetFolders returns folder list as map[name]fldMeta
func (a *App) GetFolders() (map[string]map[string]string, error) {
	fldMap, err := a.client.getFlds()
	if err != nil {
		return nil, err
	}

	out := make(map[string]map[string]string)
	for name, key := range fldMap {
		out[name] = map[string]string{
			"folderId":  objPid(key),
			"folderKey": hex.EncodeToString(key),
		}
	}
	return out, nil
}

// CreateFolder creates a new folder
func (a *App) CreateFolder(name string) error {
	return a.client.mkFld(name)
}

// RenameFolder renames an existing folder
func (a *App) RenameFolder(oldName, newName string) error {
	return a.client.renameFld(oldName, newName)
}

// DeleteFolder deletes a folder
func (a *App) DeleteFolder(name string) error {
	return a.client.delFld(name)
}

// TrimFolder trims orphan files from a folder
func (a *App) TrimFolder(folderName string, activePids []string) (string, error) {
	return a.client.trimFld(folderName, activePids)
}

// GetFiles loads file list for the specified folder
func (a *App) GetFiles(folderName string) (*FolderContents, error) {
	fPid, fKey, flMap, err := a.client.getFiles(folderName)
	if err != nil {
		return nil, err
	}

	a.mapMu.Lock()
	a.currentFld = folderName
	a.currentFlMap = flMap
	a.mapMu.Unlock()

	// Update local proxy context for streaming
	a.proxy.UpdateContext(a.client, flMap)

	filesOut := make(map[string]FileEntry)
	for name, info := range flMap {
		var sz int64
		var pid string
		var fkHex string
		if len(info) >= 52 {
			fk := info[:44]
			pid = objPid(fk)
			fkHex = hex.EncodeToString(fk)
			sz = int64(Opsec.DecodeInt(info[44:52]))
		}
		filesOut[name] = FileEntry{
			Name:    name,
			FilePid: pid,
			FileKey: fkHex,
			RawInfo: hex.EncodeToString(info),
			Size:    sz,
		}
	}

	return &FolderContents{
		FolderId:  fPid,
		FolderKey: hex.EncodeToString(fKey),
		Files:     filesOut,
	}, nil
}

// RenameFile renames a file
func (a *App) RenameFile(folderName, oldName, newName string) error {
	return a.client.renameFile(folderName, oldName, newName)
}

// DeleteFile deletes a file
func (a *App) DeleteFile(folderName, fileName string) error {
	return a.client.deleteFile(folderName, fileName)
}

// BeginFileUpload starts a streaming upload session by creating a temp file in ./temp
func (a *App) BeginFileUpload(folderName, fileName string, totalSize int64, fileIdx int, thumbBase64 string) (string, error) {
	_ = os.MkdirAll("./temp", 0755)
	tmpFile, err := os.CreateTemp("./temp", "mh-raw-*.tmp")
	if err != nil {
		return "", err
	}

	var thumbBytes []byte
	if thumbBase64 != "" {
		thumbBytes, _ = base64.StdEncoding.DecodeString(thumbBase64)
	}

	uploadId := hex.EncodeToString(Bencrypt.Random(16))
	session := &UploadSession{
		folderName: folderName,
		fileName:   fileName,
		totalSize:  totalSize,
		fileIdx:    fileIdx,
		thumbBytes: thumbBytes,
		tmpFile:    tmpFile,
		tmpPath:    tmpFile.Name(),
	}

	a.upMu.Lock()
	a.uploadSessions[uploadId] = session
	a.upMu.Unlock()

	return uploadId, nil
}

// AppendFileUploadChunk appends a base64 encoded chunk to the temp file
func (a *App) AppendFileUploadChunk(uploadId, chunkBase64 string) error {
	a.upMu.Lock()
	session, exists := a.uploadSessions[uploadId]
	a.upMu.Unlock()

	if !exists || session.tmpFile == nil {
		return errors.New("Invalid upload session")
	}

	data, err := base64.StdEncoding.DecodeString(chunkBase64)
	if err != nil {
		return err
	}

	_, err = session.tmpFile.Write(data)
	return err
}

// FinishFileUpload closes the temp file and executes the encrypted upload pipeline
func (a *App) FinishFileUpload(uploadId string) error {
	a.upMu.Lock()
	session, exists := a.uploadSessions[uploadId]
	if exists {
		delete(a.uploadSessions, uploadId)
	}
	a.upMu.Unlock()

	if !exists || session.tmpFile == nil {
		return errors.New("Invalid upload session")
	}

	_ = session.tmpFile.Close()
	defer os.Remove(session.tmpPath)

	a.uploadCancel.Store(false)
	return a.client.uploadFileNamed(a.ctx, session.folderName, session.fileName, session.tmpPath, session.thumbBytes, &a.uploadCancel, func(loaded, total int64, speed float64) {
		// Calculate remote transfer progress from 50% to 95%
		percent := 50 + int((float64(loaded)/float64(max(total, 1)))*45)
		if percent > 95 {
			percent = 95
		}
		runtime.EventsEmit(a.ctx, "file_progress", map[string]interface{}{
			"fileIdx":  session.fileIdx,
			"fileName": session.fileName,
			"loaded":   loaded,
			"total":    total,
			"speed":    speed,
			"percent":  percent,
		})
	})
}

// CancelFileUpload cleans up an in-flight upload session and temp file
func (a *App) CancelFileUpload(uploadId string) {
	a.upMu.Lock()
	session, exists := a.uploadSessions[uploadId]
	if exists {
		delete(a.uploadSessions, uploadId)
	}
	a.upMu.Unlock()

	if exists && session.tmpFile != nil {
		_ = session.tmpFile.Close()
		_ = os.Remove(session.tmpPath)
	}
}

// SelectAndUploadFiles opens a native file dialog and uploads selected files using temp files
func (a *App) SelectAndUploadFiles(folderName string) (int, error) {
	paths, err := runtime.OpenMultipleFilesDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Select Files to Upload",
	})
	if err != nil || len(paths) == 0 {
		return 0, err
	}

	a.uploadCancel.Store(false)
	uploadedCount := 0

	runtime.EventsEmit(a.ctx, "upload_started", map[string]interface{}{
		"totalFiles": len(paths),
	})

	for i, path := range paths {
		if a.uploadCancel.Load() {
			runtime.EventsEmit(a.ctx, "upload_cancelled", map[string]interface{}{"fileIdx": i})
			break
		}

		fileName := filepath.Base(path)
		runtime.EventsEmit(a.ctx, "file_progress", map[string]interface{}{
			"fileIdx":  i,
			"fileName": fileName,
			"percent":  0,
		})

		err := a.client.uploadFileNamed(a.ctx, folderName, fileName, path, nil, &a.uploadCancel, func(loaded, total int64, speed float64) {
			percent := int((float64(loaded) / float64(max(total, 1))) * 100)
			runtime.EventsEmit(a.ctx, "file_progress", map[string]interface{}{
				"fileIdx":  i,
				"fileName": fileName,
				"loaded":   loaded,
				"total":    total,
				"speed":    speed,
				"percent":  percent,
			})
		})

		if err != nil {
			if err.Error() == "UPLOAD_CANCELLED" {
				runtime.EventsEmit(a.ctx, "upload_cancelled", map[string]interface{}{"fileIdx": i})
				break
			}
			runtime.EventsEmit(a.ctx, "file_failed", map[string]interface{}{
				"fileIdx":  i,
				"fileName": fileName,
				"error":    err.Error(),
			})
			return uploadedCount, err
		}

		uploadedCount++
		runtime.EventsEmit(a.ctx, "file_completed", map[string]interface{}{
			"fileIdx":  i,
			"fileName": fileName,
		})
	}

	runtime.EventsEmit(a.ctx, "upload_finished", map[string]interface{}{
		"uploadedCount": uploadedCount,
	})
	return uploadedCount, nil
}

// CancelUpload signals cancel for active uploads
func (a *App) CancelUpload() {
	a.uploadCancel.Store(true)
}

// DownloadFile prompts for a save path and streams decrypted file
func (a *App) DownloadFile(folderName, fileName, filePid, fileKeyHex string) error {
	savePath, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "Save File As",
		DefaultFilename: fileName,
	})
	if err != nil || savePath == "" {
		return err
	}

	a.downCancel.Store(false)
	runtime.EventsEmit(a.ctx, "download_started", map[string]interface{}{
		"fileName": fileName,
	})

	err = a.client.downloadFile(a.ctx, folderName, fileName, filePid, fileKeyHex, savePath, &a.downCancel, func(loaded, total int64, speed float64) {
		percent := int((float64(loaded) / float64(max(total, 1))) * 100)
		runtime.EventsEmit(a.ctx, "download_progress", map[string]interface{}{
			"fileName": fileName,
			"loaded":   loaded,
			"total":    total,
			"speed":    speed,
			"percent":  percent,
		})
	})

	if err != nil {
		runtime.EventsEmit(a.ctx, "download_failed", map[string]interface{}{
			"fileName": fileName,
			"error":    err.Error(),
		})
		return err
	}

	runtime.EventsEmit(a.ctx, "download_completed", map[string]interface{}{
		"fileName": fileName,
		"path":     savePath,
	})
	return nil
}

// LoadMediaData decrypts media payload into Base64 for webview image/text/pdf preview
func (a *App) LoadMediaData(folderId, filePid, fileKeyHex string, origSize int64) (string, error) {
	key, err := hex.DecodeString(fileKeyHex)
	if err != nil || len(key) < 32 {
		return "", errors.New("Invalid file key")
	}

	resolvedFolderId := folderId
	if pid, _, err := a.client.resolveFolder(folderId); err == nil {
		resolvedFolderId = pid
	}

	smx := new(Bencrypt.SymMaster)
	if err := smx.Init("gcmx1", key[:32]); err != nil {
		return "", err
	}
	ciphSz := smx.AfterSize(origSize)

	datUrl := fmt.Sprintf("%s/api/media/%s/%s/dat", a.client.server, resolvedFolderId, filePid)
	reader := newChunkedRangeReader(datUrl, ciphSz, TransferChunkSize, a.client.httpClient, nil, nil)
	defer reader.Close()

	buf := new(bytes.Buffer)
	if err := smx.DeFile(reader, ciphSz, buf); err != nil {
		return "", err
	}

	data := buf.Bytes()
	if origSize > 0 && int64(len(data)) >= origSize {
		data = data[:origSize]
	}

	return base64.StdEncoding.EncodeToString(data), nil
}

// CancelDownload cancels active download
func (a *App) CancelDownload() {
	a.downCancel.Store(true)
}

// GetStreamUrl returns local HTTP streaming proxy URL for media playback
func (a *App) GetStreamUrl(folderPid, fileName string) string {
	return fmt.Sprintf("http://127.0.0.1:%d/stream/%s/%s", a.proxy.GetPort(), folderPid, url.PathEscape(fileName))
}

// GetThumbUrl returns local HTTP thumbnail URL
func (a *App) GetThumbUrl(folderPid, filePid string) string {
	return fmt.Sprintf("http://127.0.0.1:%d/thumb/%s/%s", a.proxy.GetPort(), folderPid, filePid)
}

// RegisterFileStreaming registers file key in proxy for streaming
func (a *App) RegisterFileStreaming(filePid string, fileKeyHex string) {
	key, err := hex.DecodeString(fileKeyHex)
	if err == nil {
		a.proxy.RegisterFileKey(filePid, key)
	}
}

// ExportShareToken exports folder share token
func (a *App) ExportShareToken(folderName, password string) (string, error) {
	return a.client.exportShareToken(folderName, password)
}

// ImportShareToken imports folder share token
func (a *App) ImportShareToken(tokenText, password string) (map[string]string, error) {
	name, key, err := a.client.importShareToken(tokenText, password)
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"name":      name,
		"folderId":  objPid(key),
		"folderKey": hex.EncodeToString(key),
	}, nil
}

// ChangePassword changes user password and re-encrypts userdata
func (a *App) ChangePassword(newPassword string) error {
	return a.client.changePassword(newPassword)
}

// DeleteAccount deletes current user account
func (a *App) DeleteAccount() error {
	uHash, _, _ := a.client.getAuthInfo()
	if err := a.client.deleteUserData(uHash); err != nil {
		return err
	}
	a.Logout()
	return nil
}
