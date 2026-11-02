package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/k-atusa/USAG-Lib/Bencrypt"
)

// Pepper constant for key derivation
const SecretPepper = "_PROJECT_WHY_MEDIAHUB_PEPPER_2026_!@#$"

// Default chunk size for transfers
const TransferChunkSize = 2 * 1024 * 1024

// Application runtime configuration
type Config struct {
	Server    string `json:"server"`
	SafeTLS   bool   `json:"safetls"`
	ProxyPort int    `json:"proxyPort,omitempty"`
}

// Global configuration instance
var cfg Config

// Initialize runtime directory and configuration
func initEnv() {
	// Locate executable directory
	exePath, _ := os.Executable()
	realPath, _ := filepath.EvalSymlinks(exePath)
	if realPath != "" {
		_ = os.Chdir(filepath.Dir(realPath))
	}

	// Set default configuration values
	configPath := "./config.json"
	cfg = Config{
		Server:    "http://localhost",
		SafeTLS:   true,
		ProxyPort: 18080,
	}

	// Load or create configuration file
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		file, _ := json.MarshalIndent(cfg, "", "  ")
		_ = os.WriteFile(configPath, file, 0644)
	} else {
		file, _ := os.ReadFile(configPath)
		_ = json.Unmarshal(file, &cfg)
		if cfg.ProxyPort <= 0 {
			cfg.ProxyPort = 18080
		}
	}

	// Ensure temp directory exists
	_ = os.MkdirAll("./temp", 0755)
}

// Create configured HTTP client with TLS settings
func newHTTPClient(safeTLS bool) *http.Client {
	// Setup transport with TLS skip verify if safeTLS is disabled
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !safeTLS,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
	}
	return &http.Client{
		Transport: tr,
	}
}

// Derive user PID hex string from store key
func usrPid(key []byte) string {
	hash := Bencrypt.SHA3256(key)
	return hex.EncodeToString(hash[:16])
}

// Derive object PID hex string from object key
func objPid(key []byte) string {
	if len(key) < 44 {
		return ""
	}
	return hex.EncodeToString(key[32:44])
}

// Derive stream chunk IV with Little Endian counter XOR
func mkiv(g []byte, c uint64) []byte {
	iv := make([]byte, len(g))
	copy(iv, g)
	counterBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(counterBytes, c)
	for i := 0; i < 8; i++ {
		iv[4+i] ^= counterBytes[i]
	}
	return iv
}

// Create delete request with user hash header
func newDeleteReq(url, uHash string) *http.Request {
	req, _ := http.NewRequest(http.MethodDelete, url, nil)
	if req != nil && uHash != "" {
		req.Header.Set("X-User-Hash", uHash)
	}
	return req
}

// Progress callback signature for file transfers
type ProgressCallback func(loaded int64, total int64, speed float64)

// Stream data from remote server via HTTP Range chunks
type ChunkedRangeReader struct {
	url        string
	totalSize  int64
	chunkSize  int64
	client     *http.Client
	progCb     ProgressCallback
	offset     int64
	buffer     *bytes.Buffer
	t0         time.Time
	wb         int64
	isCanceled *atomic.Bool
}

// Construct new chunked range reader instance
func newChunkedRangeReader(url string, totalSize int64, chunkSize int64, client *http.Client, progCb ProgressCallback, isCanceled *atomic.Bool) *ChunkedRangeReader {
	if chunkSize <= 0 {
		chunkSize = TransferChunkSize
	}
	return &ChunkedRangeReader{
		url:        url,
		totalSize:  totalSize,
		chunkSize:  chunkSize,
		client:     client,
		progCb:     progCb,
		offset:     0,
		buffer:     new(bytes.Buffer),
		t0:         time.Now(),
		wb:         0,
		isCanceled: isCanceled,
	}
}

// Read next decrypted bytes buffer slice
func (r *ChunkedRangeReader) Read(p []byte) (int, error) {
	needed := len(p)
	for int64(r.buffer.Len()) < int64(needed) && r.offset < r.totalSize {
		// Check cancellation flag
		if r.isCanceled != nil && r.isCanceled.Load() {
			return 0, errors.New("TRANSFER_CANCELLED")
		}

		// Calculate chunk byte boundaries
		fetchSize := r.chunkSize
		if r.totalSize-r.offset < fetchSize {
			fetchSize = r.totalSize - r.offset
		}
		fetchEnd := r.offset + fetchSize - 1

		// Fetch chunk from server
		req, err := http.NewRequest(http.MethodGet, r.url, nil)
		if err != nil {
			return 0, err
		}
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", r.offset, fetchEnd))

		res, err := r.client.Do(req)
		if err != nil {
			return 0, err
		}

		if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusPartialContent {
			res.Body.Close()
			return 0, fmt.Errorf("Download chunk failed: HTTP %d", res.StatusCode)
		}

		chunk, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			return 0, err
		}

		if int64(len(chunk)) != fetchSize {
			return 0, fmt.Errorf("Chunk size mismatch: expected %d, got %d", fetchSize, len(chunk))
		}

		// Append data to buffer
		r.buffer.Write(chunk)
		r.offset += int64(len(chunk))
		r.wb += int64(len(chunk))

		// Report progress interval
		now := time.Now()
		el := now.Sub(r.t0).Seconds()
		if el >= 0.5 && r.progCb != nil {
			r.progCb(r.offset, r.totalSize, float64(r.wb)/el)
			r.t0 = now
			r.wb = 0
		}
	}

	n, err := r.buffer.Read(p)
	if err == io.EOF && r.offset < r.totalSize {
		return n, nil
	}
	return n, err
}

// Close range reader and release internal buffer
func (r *ChunkedRangeReader) Close() error {
	r.buffer.Reset()
	return nil
}
