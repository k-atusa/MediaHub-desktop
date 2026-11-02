package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/k-atusa/USAG-Lib/Bencrypt"
	"github.com/k-atusa/USAG-Lib/Opsec"
)

// Regular expressions for path and header matching
var (
	rangeRegex1 = regexp.MustCompile(`^bytes=(\d+)-(\d*)`)
	rangeRegex2 = regexp.MustCompile(`^bytes=-(\d+)`)
	streamRegex = regexp.MustCompile(`^/stream/([^/]+)/(.*)$`)
	thumbRegex  = regexp.MustCompile(`^/thumb/([^/]+)/([^/]+)$`)
)

// Local HTTP media streaming and thumbnail proxy server
type Proxy struct {
	port       int
	server     *http.Server
	listener   net.Listener
	client     *Client
	flMap      map[string][]byte
	fkByPid    map[string][]byte
	ivCache    map[string][]byte
	chunkCache map[string][]byte
	cacheKeys  []string
	mu         sync.Mutex
}

// Construct new local streaming proxy instance
func NewProxy(port int) *Proxy {
	if port <= 0 {
		port = 18080
	}
	return &Proxy{
		port:       port,
		flMap:      make(map[string][]byte),
		fkByPid:    make(map[string][]byte),
		ivCache:    make(map[string][]byte),
		chunkCache: make(map[string][]byte),
	}
}

// Start proxy server on local TCP listener
func (p *Proxy) Start(client *Client) error {
	p.client = client
	addr := fmt.Sprintf("127.0.0.1:%d", p.port)

	// Attempt binding to designated port or fallback to dynamic port
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
	}
	p.listener = ln
	p.port = ln.Addr().(*net.TCPAddr).Port

	// Register HTTP route handlers
	mux := http.NewServeMux()
	mux.HandleFunc("/stream/", p.handleStream)
	mux.HandleFunc("/thumb/", p.handleThumb)

	p.server = &http.Server{Handler: mux}

	// Serve HTTP requests in background routine
	go func() {
		_ = p.server.Serve(ln)
	}()

	return nil
}

// Stop proxy server and close listener
func (p *Proxy) Stop() {
	if p.server != nil {
		_ = p.server.Close()
	}
}

// GetPort returns the active listening port
func (p *Proxy) GetPort() int {
	return p.port
}

// UpdateContext refreshes folder file keys and invalidates caches
func (p *Proxy) UpdateContext(client *Client, flMap map[string][]byte) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Update active client reference
	p.client = client
	p.flMap = make(map[string][]byte, len(flMap))
	p.fkByPid = make(map[string][]byte, len(flMap))

	// Index file keys by name and PID
	for k, v := range flMap {
		p.flMap[k] = v
		if len(v) >= 44 {
			pid := objPid(v[:44])
			p.fkByPid[pid] = v[:44]
		}
	}

	// Clear cached chunks and IVs
	p.ivCache = make(map[string][]byte)
	p.chunkCache = make(map[string][]byte)
	p.cacheKeys = nil
}

// RegisterFileKey explicitly maps a file PID to its decryption key
func (p *Proxy) RegisterFileKey(filePid string, fileKey []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(fileKey) >= 32 {
		p.fkByPid[filePid] = fileKey
	}
}

// Fetch or retrieve cached global IV for media stream
func (p *Proxy) getIV(fPid, fpid string) []byte {
	cacheKey := fPid + "_" + fpid
	p.mu.Lock()
	if iv, ok := p.ivCache[cacheKey]; ok {
		p.mu.Unlock()
		return iv
	}
	client := p.client
	p.mu.Unlock()

	if client == nil {
		return nil
	}

	// Request first 12 bytes containing stream IV
	urlStr := fmt.Sprintf("%s/api/media/%s/%s/dat", client.server, fPid, fpid)
	req, err := http.NewRequest(http.MethodGet, urlStr, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Range", "bytes=0-11")

	res, err := client.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusPartialContent {
		return nil
	}

	// Read and store IV
	buf, err := io.ReadAll(res.Body)
	if err != nil || len(buf) != 12 {
		return nil
	}

	p.mu.Lock()
	p.ivCache[cacheKey] = buf
	p.mu.Unlock()
	return buf
}

// Fetch, decrypt, and cache a 1MB stream chunk
func (p *Proxy) getChunk(fPid, fpid string, aesKey []byte, origSz int64, idx int64, gIV []byte) []byte {
	cacheKey := fmt.Sprintf("%s_%s_%d", fPid, fpid, idx)
	p.mu.Lock()
	if chunk, ok := p.chunkCache[cacheKey]; ok {
		p.mu.Unlock()
		return chunk
	}
	client := p.client
	p.mu.Unlock()

	if client == nil {
		return nil
	}

	// Calculate chunk payload and tag boundaries
	const PL int64 = 1048576
	const CL int64 = PL + 16

	cS := 12 + idx*CL
	pLen := PL
	if origSz-idx*PL < pLen {
		pLen = origSz - idx*PL
	}
	cLen := pLen + 16
	cE := cS + cLen - 1

	// Request encrypted chunk from remote server
	urlStr := fmt.Sprintf("%s/api/media/%s/%s/dat", client.server, fPid, fpid)
	req, err := http.NewRequest(http.MethodGet, urlStr, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", cS, cE))

	res, err := client.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusPartialContent {
		return nil
	}

	buf, err := io.ReadAll(res.Body)
	if err != nil || int64(len(buf)) != cLen {
		return nil
	}

	// Decrypt chunk with AES-GCM
	iv := mkiv(gIV, uint64(idx))
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}

	plain, err := gcm.Open(nil, iv, buf, nil)
	if err != nil {
		return nil
	}

	// Store plain chunk in LRU cache
	p.mu.Lock()
	p.chunkCache[cacheKey] = plain
	p.cacheKeys = append(p.cacheKeys, cacheKey)
	if len(p.cacheKeys) > 16 {
		oldest := p.cacheKeys[0]
		p.cacheKeys = p.cacheKeys[1:]
		delete(p.chunkCache, oldest)
	}
	p.mu.Unlock()

	return plain
}

// Handle HTTP Range media streaming requests
func (p *Proxy) handleStream(w http.ResponseWriter, r *http.Request) {
	// Enable CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Range")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Extract folder and file target from path
	path, err := url.PathUnescape(r.URL.Path)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	m := streamRegex.FindStringSubmatch(path)
	if len(m) < 3 {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	fPid := m[1]
	fName := m[2]

	// Lookup file info and active client
	p.mu.Lock()
	flInfo, ok := p.flMap[fName]
	client := p.client
	p.mu.Unlock()

	if !ok || len(flInfo) < 52 || client == nil {
		http.Error(w, "File Not Found", http.StatusNotFound)
		return
	}

	// Extract crypto keys and original size
	fk := flInfo[:44]
	aesKey := fk[:32]
	origSz := int64(Opsec.DecodeInt(flInfo[44:52]))
	fpid := objPid(fk)

	const PL int64 = 1048576

	rS := int64(0)
	rE := origSz - 1
	partial := false

	// Parse HTTP Range header
	rangeHdr := r.Header.Get("Range")
	if rangeHdr != "" {
		if rm := rangeRegex1.FindStringSubmatch(rangeHdr); len(rm) > 1 {
			rS, _ = strconv.ParseInt(rm[1], 10, 64)
			if rm[2] != "" {
				rE, _ = strconv.ParseInt(rm[2], 10, 64)
			}
			partial = true
		} else if rm2 := rangeRegex2.FindStringSubmatch(rangeHdr); len(rm2) > 1 {
			suffix, _ := strconv.ParseInt(rm2[1], 10, 64)
			rS = origSz - suffix
			if rS < 0 {
				rS = 0
			}
			partial = true
		}
	}

	// Verify range bounds
	if rS > rE || rS >= origSz {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", origSz))
		http.Error(w, "Requested Range Not Satisfiable", http.StatusRequestedRangeNotSatisfiable)
		return
	}

	fi := rS / PL
	li := rE / PL
	cLen := rE - rS + 1

	// Detect content MIME type
	ext := strings.ToLower(filepath.Ext(fName))
	mimeType := mime.TypeByExtension(ext)
	if mimeType == "" {
		switch ext {
		case ".mp4", ".mov":
			mimeType = "video/mp4"
		case ".webm":
			mimeType = "video/webm"
		case ".mkv":
			mimeType = "video/x-matroska"
		case ".png":
			mimeType = "image/png"
		case ".jpg", ".jpeg":
			mimeType = "image/jpeg"
		case ".webp":
			mimeType = "image/webp"
		case ".gif":
			mimeType = "image/gif"
		case ".svg":
			mimeType = "image/svg+xml"
		case ".pdf":
			mimeType = "application/pdf"
		default:
			mimeType = "application/octet-stream"
		}
	}

	// Set response headers
	w.Header().Set("Content-Type", mimeType)
	w.Header().Set("Content-Length", strconv.FormatInt(cLen, 10))
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Cache-Control", "no-store")

	if partial {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", rS, rE, origSz))
		w.WriteHeader(http.StatusPartialContent)
	} else {
		w.WriteHeader(http.StatusOK)
	}

	// Fetch media IV
	gIV := p.getIV(fPid, fpid)
	if len(gIV) != 12 {
		return
	}

	// Stream decrypted chunks sequentially
	for ci := fi; ci <= li; ci++ {
		chunk := p.getChunk(fPid, fpid, aesKey, origSz, ci, gIV)
		if chunk == nil {
			break
		}

		base := ci * PL
		a := rS - base
		if a < 0 {
			a = 0
		}
		b := rE - base
		if b >= int64(len(chunk)) {
			b = int64(len(chunk)) - 1
		}

		if a <= b && a < int64(len(chunk)) {
			if _, err := w.Write(chunk[a : b+1]); err != nil {
				break
			}
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		}
	}
}

// Handle HTTP requests for decrypted JPEG thumbnails
func (p *Proxy) handleThumb(w http.ResponseWriter, r *http.Request) {
	// Enable CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Parse path parameters
	m := thumbRegex.FindStringSubmatch(r.URL.Path)
	if len(m) < 3 {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	fPid := m[1]
	filePid := m[2]

	// Lookup client and key
	p.mu.Lock()
	client := p.client
	fileKey, ok := p.fkByPid[filePid]
	p.mu.Unlock()

	if client == nil || !ok || len(fileKey) < 32 {
		http.Error(w, "Thumbnail Not Available", http.StatusNotFound)
		return
	}

	// Download encrypted thumbnail from remote server
	urlStr := fmt.Sprintf("%s/api/media/%s/%s/thumb", client.server, fPid, filePid)
	res, err := client.httpClient.Get(urlStr)
	if err != nil {
		http.Error(w, "Failed to load thumbnail", http.StatusBadGateway)
		return
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		http.Error(w, "Thumbnail not found", http.StatusNotFound)
		return
	}

	enc, err := io.ReadAll(res.Body)
	if err != nil || len(enc) == 0 {
		http.Error(w, "Empty thumbnail", http.StatusNotFound)
		return
	}

	// Decrypt thumbnail using GCM1
	sm := new(Bencrypt.SymMaster)
	if err := sm.Init("gcm1", fileKey[:32]); err != nil {
		http.Error(w, "Decryption init failed", http.StatusInternalServerError)
		return
	}

	dec, err := sm.DeBin(enc)
	if err != nil {
		http.Error(w, "Decryption failed", http.StatusInternalServerError)
		return
	}

	// Respond with decrypted JPEG
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Content-Length", strconv.Itoa(len(dec)))
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(dec)
}

