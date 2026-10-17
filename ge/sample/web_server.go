// test823 : project WHY MediaHub
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

//go:embed all:public
var publicFS embed.FS

// server config
type Config struct {
	StorageDir string `json:"storage"`
	Port       string `json:"port"`
	CertFile   string `json:"cert"`
	KeyFile    string `json:"key"`
	InviteCode string `json:"invite"`
	Notice     string `json:"notice"`
}

var cfg Config

// init environment
func initEnv() {
	// move to executable path
	exePath, _ := os.Executable()
	realPath, _ := filepath.EvalSymlinks(exePath)
	os.Chdir(filepath.Dir(realPath))

	// set default value
	configPath := "./config/config.json"
	cfg = Config{
		StorageDir: "./",
		Port:       "443",
		CertFile:   "./certs/cert.pem",
		KeyFile:    "./certs/key.pem",
		InviteCode: "",
		Notice:     "",
	}

	// load config, make new if not exists
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		log.Printf("failed to create config directory: %v", err)
	}
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		file, _ := json.MarshalIndent(cfg, "", "  ")
		os.WriteFile(configPath, file, 0644)
		log.Println("config.json file not exists, created")
	} else {
		file, _ := os.ReadFile(configPath)
		json.Unmarshal(file, &cfg)
	}

	// make directories
	os.MkdirAll(filepath.Join(cfg.StorageDir, "users"), 0755)
	os.MkdirAll(filepath.Join(cfg.StorageDir, "data"), 0755)

	// make certificate if not exists
	certDir := filepath.Dir(cfg.CertFile)
	if err := os.MkdirAll(certDir, 0755); err != nil {
		log.Printf("failed to create certs directory: %v", err)
	}
	if _, err := os.Stat(cfg.CertFile); os.IsNotExist(err) {
		log.Println("making self-signed certificate")
		makeCert(cfg.CertFile, cfg.KeyFile)
	}
}

// serve static files in public or embeddedFS with SPA fallback
func serveFrontend() http.Handler {
	var fsys http.FileSystem
	if info, err := os.Stat("./public"); err == nil && info.IsDir() {
		fsys = http.Dir("./public")
	} else {
		sub, err := fs.Sub(publicFS, "public")
		if err != nil {
			log.Fatalf("failed to initialize embedded filesystem: %v", err)
		}
		fsys = http.FS(sub)
	}
	fileServer := http.FileServer(fsys)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path != "" {
			f, err := fsys.Open(path)
			if err == nil {
				f.Close()
				fileServer.ServeHTTP(w, r)
				return
			}
		}
		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	})
}

// handles userdata
func serveUser(w http.ResponseWriter, r *http.Request) {
	// URL: /api/userdata/{user_hash}
	userHash := strings.TrimPrefix(r.URL.Path, "/api/userdata/")
	if userHash == "" || strings.Contains(userHash, "/") {
		postError(w, "Invalid User Hash", http.StatusBadRequest)
		return
	}

	path := filepath.Join(cfg.StorageDir, "users", filepath.Clean(userHash))
	switch r.Method {
	case http.MethodGet: // read userdata
		http.ServeFile(w, r, path)
	case http.MethodPost: // create/update userdata
		isNewUser := false
		if _, err := os.Stat(path); os.IsNotExist(err) {
			isNewUser = true
		}

		if isNewUser && cfg.InviteCode != "" {
			// check if user is changing PW
			oldHash := r.Header.Get("X-Old-Hash")
			oldPath := ""
			if oldHash != "" && !strings.Contains(oldHash, "/") && !strings.Contains(oldHash, "\\") {
				oldPath = filepath.Join(cfg.StorageDir, "users", filepath.Clean(oldHash))
			}

			// check old account or invite code
			if oldPath != "" {
				if info, err := os.Stat(oldPath); err != nil || info.IsDir() {
					postError(w, "Invalid Old User", http.StatusForbidden)
					return
				}
			} else {
				if r.Header.Get("X-Invite-Code") != cfg.InviteCode {
					postError(w, "Invalid Invite Code", http.StatusForbidden)
					return
				}
			}
		}

		os.MkdirAll(filepath.Dir(path), 0700)
		save(w, r, path)
	case http.MethodDelete: // delete userdata
		if _, err := os.Stat(path); os.IsNotExist(err) {
			time.Sleep(1500 * time.Millisecond)
		} else {
			os.Remove(path)
		}
		w.WriteHeader(http.StatusOK)
	default:
		postError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// handles folder metadata
func serveMeta(w http.ResponseWriter, r *http.Request) {
	// URL: /api/storage/{folder_pid}/names
	target := strings.TrimPrefix(r.URL.Path, "/api/storage/")
	parts := strings.Split(target, "/")
	if len(parts) < 2 {
		postError(w, "Folder ID and Data Type Required", http.StatusBadRequest)
		return
	}
	folderID, metaType := parts[0], parts[1]
	if metaType != "names" {
		postError(w, "Invalid Metadata Type", http.StatusBadRequest)
		return
	}

	// check if folder creation
	path := filepath.Join(cfg.StorageDir, "data", filepath.Clean(folderID), "names")
	isCreation := false
	if r.Method == http.MethodPost {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			isCreation = true
		}
	}

	// Folder creation or deletion needs user validation
	if r.Method == http.MethodDelete || isCreation {
		if !authUser(w, r) {
			return
		}
	}

	switch r.Method {
	case http.MethodGet: // read metadata
		http.ServeFile(w, r, path)
	case http.MethodPost: // create/update metadata
		os.MkdirAll(filepath.Dir(path), 0755)
		save(w, r, path)
	case http.MethodDelete: // delete metadata
		os.RemoveAll(filepath.Dir(path))
		w.WriteHeader(http.StatusOK)
	default:
		postError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// handles media files
func serveMedia(w http.ResponseWriter, r *http.Request) {
	// URL: /api/media/{folder_pid}/{file_pid}/{dat|thumb}
	target := strings.TrimPrefix(r.URL.Path, "/api/media/")
	parts := strings.Split(target, "/")
	if len(parts) < 3 {
		postError(w, "Folder or File ID and Data Type Required", http.StatusBadRequest)
		return
	}
	folderID, fileID, dataType := parts[0], parts[1], parts[2]
	if dataType != "dat" && dataType != "thumb" {
		postError(w, "Invalid Data Type", http.StatusBadRequest)
		return
	}

	// use filename as hex.thumb, hex.dat
	fileName := filepath.Clean(fileID) + "." + dataType
	path := filepath.Join(cfg.StorageDir, "data", filepath.Clean(folderID), fileName)

	switch r.Method {
	case http.MethodGet: // read media file
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Accept-Ranges", "bytes")
		http.ServeFile(w, r, path)
	case http.MethodPost: // create/update media file
		if !authUser(w, r) {
			return
		}
		os.MkdirAll(filepath.Dir(path), 0755)
		save(w, r, path)
	case http.MethodDelete: // delete media file
		if _, err := os.Stat(path); os.IsNotExist(err) {
			time.Sleep(1500 * time.Millisecond)
		} else {
			os.Remove(path)
		}
		w.WriteHeader(http.StatusOK)
	default:
		postError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// handles trim (orphan file deletion)
func serveTrim(w http.ResponseWriter, r *http.Request) {
	// URL: /api/trim/{folder_pid}
	if r.Method != http.MethodPost {
		postError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	folderID := strings.TrimPrefix(r.URL.Path, "/api/trim/")
	if folderID == "" || strings.Contains(folderID, "/") {
		postError(w, "Invalid Folder ID", http.StatusBadRequest)
		return
	}

	// User authentication and parse request body
	if !authUser(w, r) {
		return
	}
	var req struct {
		PIDs []string `json:"pids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		postError(w, "Invalid PID JSON", http.StatusBadRequest)
		return
	}

	// Validate all PIDs are valid hex strings
	keepSet := make(map[string]bool)
	for _, pid := range req.PIDs {
		if _, err := hex.DecodeString(pid); err != nil || pid == "" {
			postError(w, "Invalid PID", http.StatusBadRequest)
			return
		}
		keepSet[pid] = true
	}

	// Scan folder directory
	folderPath := filepath.Join(cfg.StorageDir, "data", filepath.Clean(folderID))
	entries, err := os.ReadDir(folderPath)
	if err != nil {
		postError(w, "Folder Not Found", http.StatusNotFound)
		return
	}

	// Classify files: only encrypted media files (hex.dat / hex.thumb)
	var reEncMedia = regexp.MustCompile(`^[0-9a-f]+\.(dat|thumb)$`)
	allPIDs := make(map[string]bool)
	toDelete := make(map[string]bool)
	deleteFiles := []string{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !reEncMedia.MatchString(name) {
			continue
		}

		// Extract PID from filename (everything before the last dot)
		dotIdx := strings.LastIndex(name, ".")
		pid := name[:dotIdx]
		allPIDs[pid] = true
		if !keepSet[pid] {
			toDelete[pid] = true
			deleteFiles = append(deleteFiles, filepath.Join(folderPath, name))
		}
	}

	// Safety check: retention ratio must be >= 50%
	totalUnique := len(allPIDs)
	deleteUnique := len(toDelete)
	keepUnique := totalUnique - deleteUnique
	if totalUnique == 0 {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("No encrypted media files found"))
		return
	}
	if keepUnique*2 < totalUnique {
		postError(w, fmt.Sprintf("Trim aborted: retention ratio too low (%d/%d keep, need >= 50%%)", keepUnique, totalUnique), http.StatusConflict)
		return
	}

	// Execute deletion
	deleted := 0
	for _, path := range deleteFiles {
		if err := os.Remove(path); err == nil {
			deleted++
		}
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("Trimmed %d files (%d orphan PIDs removed, %d PIDs kept)", deleted, deleteUnique, keepUnique)))
}

// handles notice fetch
func serveNotice(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		postError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"notice": cfg.Notice})
}

// return error with 0.5s delay
func postError(w http.ResponseWriter, error string, code int) {
	time.Sleep(500 * time.Millisecond)
	log.Printf("[ERROR %d] %s", code, error)
	http.Error(w, error, code)
}

// checks user exists by X-User-Hash header
func authUser(w http.ResponseWriter, r *http.Request) bool {
	userHash := r.Header.Get("X-User-Hash")
	if userHash == "" || strings.Contains(userHash, "/") || strings.Contains(userHash, "\\") {
		postError(w, "Invalid User Hash", http.StatusBadRequest)
		return false
	}
	userPath := filepath.Join(cfg.StorageDir, "users", filepath.Clean(userHash))
	if info, err := os.Stat(userPath); os.IsNotExist(err) || info.IsDir() {
		postError(w, "Authentication Failed", http.StatusForbidden)
		return false
	}
	return true
}

// overwrite or append file chunk by offset
func save(w http.ResponseWriter, r *http.Request, path string) {
	// get offset from header, default to 0
	var offset int64 = 0
	if header := r.Header.Get("X-Upload-Offset"); header != "" {
		if _, err := fmt.Sscanf(header, "%d", &offset); err != nil || offset < 0 {
			postError(w, "Invalid X-Upload-Offset Header", http.StatusBadRequest)
			return
		}
		if info, err := os.Stat(path); (err != nil && offset > 0) || (info != nil && offset > info.Size()) {
			postError(w, "Invalid Offset", http.StatusBadRequest)
			return
		}
	}

	// open or create file, truncate data after offset
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		postError(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer out.Close()
	if _, err := out.Seek(offset, io.SeekStart); err != nil || out.Truncate(offset) != nil {
		postError(w, "Seek or Truncate Error", http.StatusInternalServerError)
		return
	}

	// copy request body to file
	if _, err = io.Copy(out, r.Body); err != nil {
		postError(w, "File Write Error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Success"))
}

// cross platform optimization middleware filter
func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "..") || strings.Contains(r.URL.Path, "\\") { // block directory traversal
			postError(w, "Directory Traversal Detected", http.StatusBadRequest)
			return
		}

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Access-Control-Expose-Headers", "Content-Range, Accept-Ranges, Content-Length")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ECDSA P-256 self-signed certificate helper
func makeCert(certOut string, keyOut string) {
	// generate private key
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// set certificate validity
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, _ := rand.Int(rand.Reader, limit)

	// make certificate template
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{"K-ATUSA Programming Club"},
		},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// create certificate
	der, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)

	// write certificate
	cFile, _ := os.Create(certOut)
	defer cFile.Close()
	pem.Encode(cFile, &pem.Block{Type: "CERTIFICATE", Bytes: der})

	// write private key
	kFile, _ := os.OpenFile(keyOut, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	defer kFile.Close()
	b, _ := x509.MarshalECPrivateKey(priv)
	pem.Encode(kFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
}

func main() {
	initEnv()

	// link API and file server
	mux := http.NewServeMux()
	mux.HandleFunc("/api/userdata/", serveUser)
	mux.HandleFunc("/api/storage/", serveMeta)
	mux.HandleFunc("/api/media/", serveMedia)
	mux.HandleFunc("/api/notice", serveNotice)
	mux.HandleFunc("/api/trim/", serveTrim)
	mux.Handle("/", serveFrontend())

	// start server with TLS
	log.Printf("Server is running on port %s", cfg.Port)
	err := http.ListenAndServeTLS(":"+cfg.Port, cfg.CertFile, cfg.KeyFile, cors(mux))
	if err != nil {
		log.Fatalf("Server startup error: %v", err)
	}
}
