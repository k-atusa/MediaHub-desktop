// test793c : USAG-Lib bencrypt

package Bencrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"runtime"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/argon2"

	"github.com/cloudflare/circl/dh/x448"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/sign/ed448"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// ========== Basic Functions ==========
var SCLEAR_BACK = func(b []byte) { clear(b) }

func sclear(data []byte) { SCLEAR_BACK(data); runtime.KeepAlive(data) }

func Random(size int) []byte {
	b := make([]byte, size)
	_, err := rand.Read(b)
	if err != nil {
		panic(err) // CRNG failure is usually fatal
	}
	return b
}

func SHA3256(data []byte) []byte {
	hash := sha3.Sum256(data)
	return hash[:]
}

func SHA3512(data []byte) []byte {
	hash := sha3.Sum512(data)
	return hash[:]
}

func HMAC3256(key []byte, data []byte) []byte {
	h := hmac.New(func() hash.Hash { return sha3.New256() }, key)
	h.Write(data)
	return h.Sum(nil)
}

func HMAC3512(key []byte, data []byte) []byte {
	h := hmac.New(func() hash.Hash { return sha3.New512() }, key)
	h.Write(data)
	return h.Sum(nil)
}

type aesResult struct {
	data []byte
	err  error
}

func mkiv(g []byte, c uint64) []byte {
	// Create a copy to avoid mutating the original slice if it's reused
	iv := make([]byte, len(g))
	copy(iv, g)

	// Convert counter to 8 bytes Little Endian
	counterBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(counterBytes, c)

	// XOR bytes 4~11
	for i := 0; i < 8; i++ {
		iv[4+i] ^= counterBytes[i]
	}
	return iv
}

// make key using HMAC-SHA3-512
func Genkey(data []byte, lbl string, size int) ([]byte, error) {
	h := hmac.New(func() hash.Hash { return sha3.New512() }, data)
	h.Write([]byte(lbl))
	key := h.Sum(nil)
	if size > len(key) {
		return nil, errors.New("key size too large")
	}
	return key[:size], nil
}

// ========== Data Masker ==========
var (
	primeCandidates = [16]int64{
		15485863, 32452843, 86028121, 104395301,
		179424673, 228017633, 236887691, 345098717,
		413158511, 481230491, 563117203, 693240851,
		715225741, 812349821, 882046271, 999999937,
	}
	instance *Masker
	once     sync.Once
)

type Masker struct {
	poolSize int64
	pool     []byte
	prime    int64
}

func (m *Masker) init(poolSizeMb int) {
	m.poolSize = int64(poolSizeMb * 1048576)
	m.pool = Random(poolSizeMb * 1048576)
	m.prime = primeCandidates[Random(1)[0]%16]
}

// Get singleton instance
func GetMasker(poolSizeMb int) *Masker {
	if poolSizeMb <= 0 {
		poolSizeMb = 8
	}
	once.Do(func() {
		instance = new(Masker)
		instance.init(poolSizeMb)
	})
	return instance
}

// XOR Masking
func (m *Masker) XOR(data []byte) ([]byte, error) {
	// Trivial case handling
	L := int64(len(data))
	switch {
	case L == 0:
		return data, nil
	case L == 1:
		result := make([]byte, 1)
		result[0] = data[0] ^ m.pool[m.prime%m.poolSize]
		return result, nil
	case L > m.poolSize:
		return nil, fmt.Errorf("data length %d exceeds pool size %d", L, m.poolSize)
	}

	// pre-allocate work block
	mid := L / 2
	maxLen := L - mid
	workBlock := make([]byte, maxLen*3)
	defer func() { sclear(workBlock) }()
	buf1 := workBlock[0:maxLen:maxLen]
	buf2 := workBlock[maxLen : 2*maxLen : 2*maxLen]
	buf3 := workBlock[2*maxLen : 3*maxLen : 3*maxLen]

	left := buf1[:mid]
	right := buf2[:maxLen]
	free := buf3
	copy(left, data[:mid])
	copy(right, data[mid:])

	// 5-Round Feistel Network
	for round := 0; round < 5; round++ {
		var seed int64 = 0
		for i, b := range right {
			seed = (seed + int64(b)*int64(i+1)) % m.poolSize
		}

		nextLeft := free[:len(left)]
		for i, a := range left {
			poolIdx := (seed + int64(i)*m.prime) % m.poolSize
			nextLeft[i] = a ^ m.pool[poolIdx]
		}

		free = left[:maxLen]
		left = right
		right = nextLeft
	}

	finalResult := make([]byte, L)
	copy(finalResult, right)
	copy(finalResult[int64(len(right)):], left)
	return finalResult, nil // re-order for odd length
}

// ========== Hash Function Master ==========
type HashMaster struct {
	algo     string
	hashSize int
	keySize  int
}

func (hm *HashMaster) Init(algo string, hashSize int, keySize int) error {
	if hashSize <= 0 {
		hashSize = 32 // default 32B
	}
	if keySize <= 0 {
		keySize = 32 // default 32B
	}
	switch algo {
	case "sha3", "arg2low", "arg2st":
		hm.algo = algo
		hm.hashSize = hashSize
		hm.keySize = keySize
	default:
		return errors.New("unsupported algorithm: " + algo)
	}
	return nil
}

func (hm *HashMaster) KDF(pw []byte, salt []byte) ([]byte, []byte, error) {
	if hm.hashSize <= 0 || hm.keySize <= 0 {
		return nil, nil, errors.New("invalid hash or key size")
	}
	var lblStore, lblKeygen string
	var master []byte
	defer func() { sclear(master) }()

	// get master secret
	switch hm.algo {
	case "sha3":
		lblStore, lblKeygen = "PWHASH_SHA3", "KEYGEN_SHA3"
		data := make([]byte, 0, len(salt)+len(pw))
		data = append(data, salt...)
		data = append(data, pw...)
		defer sclear(data)
		master = SHA3512(data)
	case "arg2low":
		lblStore, lblKeygen = "PWHASH_ARG2LOW", "KEYGEN_ARG2LOW"
		master = argon2.IDKey(pw, salt, 4, 65536, 8, 64)
	case "arg2st":
		lblStore, lblKeygen = "PWHASH_ARG2ST", "KEYGEN_ARG2ST"
		master = argon2.IDKey(pw, salt, 3, 262144, 6, 64)
	default:
		return nil, nil, errors.New("algorithm not set")
	}

	// generate keys
	storeKey, err := Genkey(master, lblStore, hm.hashSize)
	if err != nil {
		return nil, nil, err
	}
	userKey, err := Genkey(master, lblKeygen, hm.keySize)
	if err != nil {
		return nil, nil, err
	}
	return storeKey, userKey, nil
}

// ========== Hash Functions ==========
// (no additional function needed)

// ========== Master Class ==========
type SymMaster struct {
	Algo string
	Key  []byte
	mask *Masker
	aes  *AES1
}

func (sm *SymMaster) Init(algo string, key []byte) error {
	sm.mask = GetMasker(-1)
	switch algo {
	case "gcm1", "gcmx1":
		if len(key) != 32 {
			return fmt.Errorf("SYM keysize must be 32: got %d", len(key))
		}
		sm.Algo = algo
		var err error
		sm.Key, err = sm.mask.XOR(key) // save key as XOR masked
		if err != nil {
			return err
		}
		sm.aes = new(AES1)
	default:
		return errors.New("unsupported algorithm: " + algo)
	}
	return nil
}

func (sm *SymMaster) AfterSize(size int64) int64 {
	switch sm.Algo {
	case "gcm1":
		return size + 28
	case "gcmx1":
		chunkSize := int64(1048576)
		c := size/chunkSize + 1
		if size != 0 && size%chunkSize == 0 {
			c -= 1
		}
		return size + 12 + (16 * c)
	default:
		return 0
	}
}

func (sm *SymMaster) Processed() int64 {
	return sm.aes.Processed()
}

func (sm *SymMaster) EnBin(data []byte) ([]byte, error) {
	// unmask key
	key, err := sm.mask.XOR(sm.Key)
	defer sclear(key)
	if err != nil {
		return nil, err
	}

	switch sm.Algo {
	case "gcm1":
		return sm.aes.EnAESGCM(key, data)
	case "gcmx1":
		in := bytes.NewReader(data)
		out := new(bytes.Buffer)
		err := sm.aes.EnAESGCMx(key, in, int64(len(data)), out, 1048576)
		if err != nil {
			return nil, err
		}
		return out.Bytes(), nil
	default:
		return nil, errors.New("algorithm not set")
	}
}

func (sm *SymMaster) DeBin(data []byte) ([]byte, error) {
	// unmask key
	key, err := sm.mask.XOR(sm.Key)
	defer sclear(key)
	if err != nil {
		return nil, err
	}

	switch sm.Algo {
	case "gcm1":
		return sm.aes.DeAESGCM(key, data)
	case "gcmx1":
		in := bytes.NewReader(data)
		out := new(bytes.Buffer)
		err := sm.aes.DeAESGCMx(key, in, int64(len(data)), out, 1048576)
		if err != nil {
			return nil, err
		}
		return out.Bytes(), nil
	default:
		return nil, errors.New("algorithm not set")
	}
}

func (sm *SymMaster) EnFile(src io.Reader, size int64, dst io.Writer) error {
	// unmask key
	key, err := sm.mask.XOR(sm.Key)
	defer sclear(key)
	if err != nil {
		return err
	}

	switch sm.Algo {
	case "gcm1":
		data, err := io.ReadAll(io.LimitReader(src, size))
		if err != nil {
			return err
		}
		enc, err := sm.aes.EnAESGCM(key, data)
		if err != nil {
			return err
		}
		_, err = dst.Write(enc)
		return err
	case "gcmx1":
		return sm.aes.EnAESGCMx(key, src, size, dst, 1048576)
	}
	return errors.New("algorithm not set")
}

func (sm *SymMaster) DeFile(src io.Reader, size int64, dst io.Writer) error {
	// unmask key
	key, err := sm.mask.XOR(sm.Key)
	defer sclear(key)
	if err != nil {
		return err
	}

	switch sm.Algo {
	case "gcm1":
		data, err := io.ReadAll(io.LimitReader(src, size))
		if err != nil {
			return err
		}
		dec, err := sm.aes.DeAESGCM(key, data)
		if err != nil {
			return err
		}
		_, err = dst.Write(dec)
		return err
	case "gcmx1":
		return sm.aes.DeAESGCMx(key, src, size, dst, 1048576)
	}
	return errors.New("algorithm not set")
}

// ========== AES Encryption ==========
type AES1 struct {
	processed int64
}

func (a *AES1) Init() { a.processed = 0 }

func (a *AES1) Processed() int64 { return atomic.LoadInt64(&a.processed) }

// AES-GCM encryption, 32B key, randomly generated 12B IV prepended to output
func (a *AES1) EnAESGCM(key []byte, data []byte) ([]byte, error) {
	// basic setup
	a.processed = 0
	iv := Random(12)
	aeskey := key

	// make AES cipher
	block, e0 := aes.NewCipher(aeskey)
	if e0 != nil {
		return nil, e0
	}
	aesgcm, e1 := cipher.NewGCM(block)
	if e1 != nil {
		return nil, e1
	}

	// encrypt
	enc := aesgcm.Seal(nil, iv, data, nil)
	a.processed = int64(len(data))

	res := make([]byte, 12+len(enc))
	copy(res[:12], iv)
	copy(res[12:], enc)
	return res, nil // format: [IV 12B][encdata][tag 16B]
}

// AES-GCM decryption, 32B key, extracts 12B IV from input
func (a *AES1) DeAESGCM(key []byte, data []byte) ([]byte, error) {
	// basic setup
	a.processed = 0
	if len(data) < 28 {
		return nil, errors.New("data too short")
	}
	iv := data[:12]
	encdata := data[12:]
	aeskey := key

	// make AES cipher
	block, e0 := aes.NewCipher(aeskey)
	if e0 != nil {
		return nil, e0
	}
	aesgcm, e1 := cipher.NewGCM(block)
	if e1 != nil {
		return nil, e1
	}

	// decrypt
	plain, e2 := aesgcm.Open(nil, iv, encdata, nil)
	if e2 != nil {
		return nil, e2
	}
	a.processed = int64(len(data))
	return plain, nil
}

// AES-GCM extended, 32B key, default chunkSize=1048576
func (a *AES1) EnAESGCMx(key []byte, src io.Reader, size int64, dst io.Writer, chunkSize int) error {
	// basic setup
	a.processed = 0
	if chunkSize <= 0 {
		chunkSize = 1048576 // 1MiB
	}
	globalIV := Random(12)
	globalKey := key
	_, e_iv := dst.Write(globalIV)
	if e_iv != nil {
		return e_iv
	}
	var memPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, chunkSize+16)
		},
	}
	thrN := runtime.NumCPU()
	if thrN <= 0 {
		thrN = 1
	}

	// make AES cipher
	block, e0 := aes.NewCipher(globalKey)
	if e0 != nil {
		return e0
	}
	aesgcm, e1 := cipher.NewGCM(block)
	if e1 != nil {
		return e1
	}

	// task setup
	var rErr error = nil
	wErr := make(chan error, 1)
	writeQue := make(chan chan aesResult, thrN*2)
	var wg sync.WaitGroup

	// Start writer goroutine
	wg.Add(1)
	go func() {
		defer func() {
			if e := recover(); e != nil {
				wErr <- e.(error) // panic to error
			}
			close(wErr)
			wg.Done()
		}()
		for ch := range writeQue {
			res := <-ch         // get result
			if res.err != nil { // quit if error occurs
				wErr <- res.err
				return
			}
			_, e := dst.Write(res.data) // write data
			if e != nil {
				wErr <- e
				return
			}
			atomic.AddInt64(&a.processed, int64(len(res.data)-16))
			if cap(res.data) >= chunkSize+16 { // return buffer
				memPool.Put(res.data[:0])
			}
		}
	}()

	// Read, submit task
	var counter uint64 = 0
	remaining := size
	loopCtrl := true
	for loopCtrl {
		// get buffer
		toRead := min(remaining, int64(chunkSize))
		buf := memPool.Get().([]byte)
		if cap(buf) < int(toRead) {
			buf = make([]byte, toRead)
		}
		buf = buf[:toRead]

		// read buffer
		_, err := io.ReadFull(src, buf)
		if err != nil {
			if err == io.EOF {
				loopCtrl = false
			} else {
				rErr = err
				break
			}
		}
		remaining -= toRead

		// make iv, submit task
		currentIV := mkiv(globalIV, counter)
		counter++
		future := make(chan aesResult, 1)
		select {
		case writeQue <- future:
		case err := <-wErr:
			return err
		}

		// encryption goroutine
		go func(m cipher.AEAD, key []byte, iv []byte, data []byte, outCh chan aesResult) {
			var r aesResult
			defer func() {
				if e := recover(); e != nil {
					r.err = e.(error) // panic to error
				}
				outCh <- r
				close(outCh)
			}()
			r.data = aesgcm.Seal(data[:0], iv, data, nil)
		}(aesgcm, globalKey, currentIV, buf, future)
		if remaining <= 0 {
			loopCtrl = false
		}
	}

	// wait for writer, return
	close(writeQue)
	wg.Wait()
	err, ok := <-wErr
	if ok && err != nil {
		return err
	}
	return rErr
}

// AES-GCM extended, 44B key (12B IV + 32B AES Key), default chunkSize=1048576
func (a *AES1) DeAESGCMx(key []byte, src io.Reader, size int64, dst io.Writer, chunkSize int) error {
	// basic setup
	a.processed = 0
	if chunkSize <= 0 {
		chunkSize = 1048576 // 1MiB
	}
	if size < 28 {
		return errors.New("cipher too short to decrypt")
	}
	globalIV := make([]byte, 12)
	_, e_iv := io.ReadFull(src, globalIV)
	if e_iv != nil {
		return e_iv
	}
	atomic.StoreInt64(&a.processed, 12)
	globalKey := key
	var memPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, chunkSize+16)
		},
	}
	thrN := runtime.NumCPU()
	if thrN <= 0 {
		thrN = 1
	}

	// make AES cipher
	block, e0 := aes.NewCipher(globalKey)
	if e0 != nil {
		return e0
	}
	aesgcm, e1 := cipher.NewGCM(block)
	if e1 != nil {
		return e1
	}

	// task setup
	var rErr error = nil
	wErr := make(chan error, 1)
	writeQue := make(chan chan aesResult, thrN*2)
	var wg sync.WaitGroup

	// Start writer goroutine
	wg.Add(1)
	go func() {
		defer func() {
			if e := recover(); e != nil {
				wErr <- e.(error) // panic to error
			}
			close(wErr)
			wg.Done()
		}()
		for ch := range writeQue {
			res := <-ch         // get result
			if res.err != nil { // quit if error occurs
				wErr <- res.err
				return
			}
			_, e := dst.Write(res.data) // write data
			if e != nil {
				wErr <- e
				return
			}
			atomic.AddInt64(&a.processed, int64(len(res.data)+16))
			if cap(res.data) >= chunkSize+16 { // return buffer
				memPool.Put(res.data[:0])
			}
		}
	}()

	// Read, submit task
	var counter uint64 = 0
	remaining := size - 12
	for remaining >= 16 {
		// get buffer
		toRead := min(int64(chunkSize+16), remaining)
		buf := memPool.Get().([]byte)
		if cap(buf) < int(toRead) {
			buf = make([]byte, toRead)
		}
		buf = buf[:toRead]

		// read buffer
		_, err := io.ReadFull(src, buf)
		if err != nil {
			if err == io.EOF {
				remaining = 0
			} else {
				rErr = err
				break
			}
		}
		remaining -= toRead

		// make iv, submit task
		currentIV := mkiv(globalIV, counter)
		counter++
		future := make(chan aesResult, 1)
		select {
		case writeQue <- future:
		case err := <-wErr:
			return err
		}

		// encryption goroutine
		go func(m cipher.AEAD, key []byte, iv []byte, data []byte, outCh chan aesResult) {
			var r aesResult
			defer func() {
				if e := recover(); e != nil {
					r.err = e.(error) // panic to error
				}
				outCh <- r
				close(outCh)
			}()
			r.data, r.err = aesgcm.Open(data[:0], iv, data, nil)
		}(aesgcm, globalKey, currentIV, buf, future)
	}

	// wait for writer, return
	close(writeQue)
	wg.Wait()
	err, ok := <-wErr
	if ok && err != nil {
		return err
	}
	return rErr
}

// ========== Asymetric Encryption Master ==========
type AsymMaster struct {
	Algo string // algo: "ecc1", "pqc1"
	ecc  *ECC1
	pqc1 *PQC1
}

func (am *AsymMaster) Init(algo string) error {
	switch algo {
	case "ecc1":
		am.Algo = algo
		am.ecc = new(ECC1)
	case "pqc1":
		am.Algo = algo
		am.pqc1 = new(PQC1)
	default:
		return errors.New("unsupported algorithm: " + algo)
	}
	return nil
}

// Generate key pair
func (am *AsymMaster) Genkey() ([]byte, []byte, error) {
	switch am.Algo {
	case "ecc1":
		return am.ecc.Genkey()
	case "pqc1":
		return am.pqc1.Genkey()
	}
	return nil, nil, errors.New("algorithm not set")
}

func (am *AsymMaster) Loadkey(public []byte, private []byte) error {
	switch am.Algo {
	case "ecc1":
		return am.ecc.Loadkey(public, private)
	case "pqc1":
		return am.pqc1.Loadkey(public, private)
	}
	return errors.New("algorithm not set")
}

func (am *AsymMaster) Encrypt(data []byte) ([]byte, error) {
	switch am.Algo {
	case "ecc1":
		return am.ecc.Encrypt(data)
	case "pqc1":
		return am.pqc1.Encrypt(data)
	}
	return nil, errors.New("algorithm not set")
}

func (am *AsymMaster) Decrypt(data []byte) ([]byte, error) {
	switch am.Algo {
	case "ecc1":
		return am.ecc.Decrypt(data)
	case "pqc1":
		return am.pqc1.Decrypt(data)
	}
	return nil, errors.New("algorithm not set")
}

func (am *AsymMaster) Sign(data []byte) ([]byte, error) {
	switch am.Algo {
	case "ecc1":
		return am.ecc.Sign(data)
	case "pqc1":
		return am.pqc1.Sign(data)
	}
	return nil, errors.New("algorithm not set")
}

func (am *AsymMaster) Verify(data []byte, signature []byte) bool {
	switch am.Algo {
	case "ecc1":
		return am.ecc.Verify(data, signature)
	case "pqc1":
		return am.pqc1.Verify(data, signature)
	}
	return false
}

// ========== ECC Encryption ==========
type ECC1 struct {
	// X448 Keys (Encryption)
	PrivX *x448.Key
	PubX  *x448.Key

	// Ed448 Keys (Signing)
	PrivEd ed448.PrivateKey
	PubEd  ed448.PublicKey

	// Format: [1B PubLen][TempPub][EncData]
}

// Generates keys: [X448 56B][Ed448 57B], (public bytes, private bytes, error)
func (e *ECC1) Genkey() ([]byte, []byte, error) {
	// 1. Generate X448 (56 bytes)
	var xPub, xPriv x448.Key
	// random bytes for private key
	if _, err := io.ReadFull(rand.Reader, xPriv[:]); err != nil {
		return nil, nil, err
	}
	x448.KeyGen(&xPub, &xPriv)
	e.PrivX = &xPriv
	e.PubX = &xPub

	// 2. Generate Ed448 (57 bytes public, 57 bytes private seed)
	edPub, edPriv, err := ed448.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	e.PubEd = edPub
	e.PrivEd = edPriv

	// 3. Serialize Public: 56 + 57 = 113
	pubBytes := make([]byte, 113)
	copy(pubBytes[:56], e.PubX[:])
	copy(pubBytes[56:], e.PubEd)

	// 4. Serialize Private: 56 + 57 = 113
	privBytes := make([]byte, 113)
	copy(privBytes[:56], e.PrivX[:])
	copy(privBytes[56:], e.PrivEd.Seed()) // Use Seed() to get the raw 57B private scalar
	return pubBytes, privBytes, nil
}

// Load keys. Public must be 113B, Private must be 113B.
func (e *ECC1) Loadkey(public []byte, private []byte) error {
	if public != nil {
		if len(public) != 113 {
			return fmt.Errorf("ECC1 keysize must be 113: got %d", len(public))
		}
		// Load X448 Public
		e.PubX = new(x448.Key)
		copy(e.PubX[:], public[:56])

		// Load Ed448 Public
		e.PubEd = make(ed448.PublicKey, ed448.PublicKeySize)
		copy(e.PubEd, public[56:])
	}

	if private != nil {
		if len(private) != 113 {
			return fmt.Errorf("ECC1 keysize must be 113: got %d", len(private))
		}
		// Load X448 Private
		e.PrivX = new(x448.Key)
		copy(e.PrivX[:], private[:56])

		// Load Ed448 Private (Re-derive full key from seed)
		e.PrivEd = ed448.NewKeyFromSeed(private[56:])
	}
	return nil
}

// Encrypt data using public key (Hybrid: ECDH + AES-GCM)
func (e *ECC1) Encrypt(data []byte) ([]byte, error) {
	// 1. Generate temp ephemeral key
	var tempPub, tempPriv x448.Key
	defer func() { sclear(tempPriv[:]) }()
	if _, err := io.ReadFull(rand.Reader, tempPriv[:]); err != nil {
		return nil, err
	}
	x448.KeyGen(&tempPub, &tempPriv)

	// 2. Get shared secret (ECDH)
	var shared x448.Key
	defer func() { sclear(shared[:]) }()
	ok := x448.Shared(&shared, &tempPriv, e.PubX)
	if !ok {
		return nil, errors.New("ECDH key exchange failed (bad public key)")
	}

	// 3. Derive Key & Encrypt with AES-GCM
	gcmKey, err := Genkey(shared[:], "KEYGEN_ECC1_ENCRYPT", 32)
	defer sclear(gcmKey)
	if err != nil {
		return nil, err
	}
	em := new(SymMaster)
	em.Init("gcm1", gcmKey)
	enc, err := em.EnBin(data)
	if err != nil {
		return nil, err
	}

	// Join to make [TempPub 56B][Enc]
	out := make([]byte, 56+len(enc))
	copy(out[:56], tempPub[:])
	copy(out[56:], enc)
	return out, nil
}

// Decrypt data using private key (Hybrid: ECDH + AES-GCM)
func (e *ECC1) Decrypt(data []byte) ([]byte, error) {
	// 1. Parse data
	if len(data) < 56 {
		return nil, errors.New("data too short")
	}
	var tempPub x448.Key
	copy(tempPub[:], data[:56])
	enc := data[56:]

	// 2. Get shared secret (ECDH)
	var shared x448.Key
	defer func() { sclear(shared[:]) }()
	ok := x448.Shared(&shared, e.PrivX, &tempPub)
	if !ok {
		return nil, errors.New("ECDH key exchange failed")
	}

	// 3. Decrypt with AES-GCM
	gcmKey, err := Genkey(shared[:], "KEYGEN_ECC1_ENCRYPT", 32)
	defer sclear(gcmKey)
	if err != nil {
		return nil, err
	}
	em := new(SymMaster)
	em.Init("gcm1", gcmKey)
	return em.DeBin(enc)
}

// Ed448 Sign (empty context is default)
func (e *ECC1) Sign(data []byte) ([]byte, error) {
	if e.PrivEd == nil {
		return nil, errors.New("private key not loaded")
	}
	// Python cryptography signs with empty context by default for Ed448
	return ed448.Sign(e.PrivEd, data, ""), nil
}

// Ed448 Verify
func (e *ECC1) Verify(data []byte, signature []byte) bool {
	if e.PubEd == nil {
		return false
	}
	return ed448.Verify(e.PubEd, data, signature, "")
}

// ========== PQC1 Encryption ==========
type PQC1 struct {
	// ECC Keys
	PubX   *x448.Key
	PrivX  *x448.Key
	PubEd  ed448.PublicKey
	PrivEd ed448.PrivateKey

	// PQC Key Bytes (Raw Bytes Storage)
	PubKEM  []byte
	PrivKEM []byte
	PubDSA  []byte
	PrivDSA []byte

	mask *Masker
}

func (p *PQC1) Genkey() ([]byte, []byte, error) {
	if p.mask == nil {
		p.mask = GetMasker(-1)
	}
	var wg sync.WaitGroup
	wg.Add(4)

	// local variables
	var err1, err2, err3, err4 error
	var pubX, privX x448.Key
	var pubEd ed448.PublicKey
	var privEd ed448.PrivateKey
	var pubKEM, privKEM, pubDSA, privDSA []byte

	// 1-1. Curve448 X448 Key Generation
	go func() {
		defer wg.Done()
		defer func() {
			if e := recover(); e != nil {
				err1 = e.(error) // panic to error
			}
		}()
		if _, err := io.ReadFull(rand.Reader, privX[:]); err != nil {
			err1 = err
			return
		}
		x448.KeyGen(&pubX, &privX)
	}()

	// 1-2. Curve448 Ed448 Key Generation
	go func() {
		defer wg.Done()
		defer func() {
			if e := recover(); e != nil {
				err2 = e.(error) // panic to error
			}
		}()
		pubEd, privEd, err2 = ed448.GenerateKey(rand.Reader)
	}()

	// 2-1. ML-KEM-1024 Key Generation
	go func() {
		defer wg.Done()
		defer func() {
			if e := recover(); e != nil {
				err3 = e.(error) // panic to error
			}
		}()
		kemPub, kemPriv, err := mlkem1024.Scheme().GenerateKeyPair()
		if err != nil {
			err3 = err
			return
		}
		pubKEM, _ = kemPub.MarshalBinary()
		privKEM, _ = kemPriv.MarshalBinary()
	}()

	// 2-2. ML-DSA-87 Key Generation
	go func() {
		defer wg.Done()
		defer func() {
			if e := recover(); e != nil {
				err4 = e.(error) // panic to error
			}
		}()
		dsaPub, dsaPriv, err := mldsa87.Scheme().GenerateKey()
		if err != nil {
			err4 = err
			return
		}
		pubDSA, _ = dsaPub.MarshalBinary()
		privDSA, _ = dsaPriv.MarshalBinary()
	}()

	// wait for all key generations to finish
	wg.Wait()
	if err1 != nil {
		return nil, nil, err1
	}
	if err2 != nil {
		return nil, nil, err2
	}
	if err3 != nil {
		return nil, nil, err3
	}
	if err4 != nil {
		return nil, nil, err4
	}

	// 3. Save and Key Join
	p.PubX, p.PrivX = &pubX, &privX
	p.PubEd, p.PrivEd = pubEd, privEd
	p.PubKEM, p.PrivKEM = pubKEM, privKEM
	p.PubDSA, p.PrivDSA = pubDSA, privDSA

	pub0 := pubX[:]
	pri0 := privX[:]
	pub1 := []byte(pubEd)
	pri1 := privEd.Seed() // 57B seed

	pubB := make([]byte, 0, 4273)
	pubB = append(pubB, pub0...)
	pubB = append(pubB, pub1...)
	pubB = append(pubB, p.PubKEM...)
	pubB = append(pubB, p.PubDSA...)

	priB := make([]byte, 0, 8177)
	priB = append(priB, pri0...)
	priB = append(priB, pri1...)
	priB = append(priB, p.PrivKEM...)
	priB = append(priB, p.PrivDSA...)

	// 4. Masking
	p.PrivKEM, err1 = p.mask.XOR(p.PrivKEM)
	p.PrivDSA, err2 = p.mask.XOR(p.PrivDSA)
	if err1 != nil {
		return nil, nil, err1
	}
	if err2 != nil {
		return nil, nil, err2
	}
	return pubB, priB, nil
}

func (p *PQC1) Loadkey(public []byte, private []byte) error {
	if p.mask == nil {
		p.mask = GetMasker(-1)
	}

	if public != nil {
		if len(public) != 4273 {
			return fmt.Errorf("PQC1 keysize must be 4273: got %d", len(public))
		}
		p.PubX = new(x448.Key)
		copy(p.PubX[:], public[:56])

		p.PubEd = make(ed448.PublicKey, 57)
		copy(p.PubEd, public[56:113])

		p.PubKEM = make([]byte, 1568)
		copy(p.PubKEM, public[113:1681])

		p.PubDSA = make([]byte, 2592)
		copy(p.PubDSA, public[1681:4273])
	}

	if private != nil {
		if len(private) != 8177 {
			return fmt.Errorf("PQC1 keysize must be 8177: got %d", len(private))
		}
		p.PrivX = new(x448.Key)
		copy(p.PrivX[:], private[:56])
		p.PrivEd = ed448.NewKeyFromSeed(private[56:113])

		var err error
		p.PrivKEM, err = p.mask.XOR(private[113:3281])
		if err != nil {
			return err
		}
		p.PrivDSA, err = p.mask.XOR(private[3281:8177])
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *PQC1) Encrypt(data []byte) ([]byte, error) {
	if p.mask == nil {
		p.mask = GetMasker(-1)
	}
	var wg sync.WaitGroup
	wg.Add(2)

	// local variables
	var err1, err2 error
	var tempPub, ssvECC x448.Key
	var kemEnc, ssvKEM []byte
	defer func() { sclear(ssvECC[:]) }()
	defer func() { sclear(ssvKEM) }()

	// 1. Ephemeral X448 tempkey generation & ECDH
	go func() {
		defer wg.Done()
		defer func() {
			if e := recover(); e != nil {
				err1 = e.(error) // panic to error
			}
		}()
		var tempPriv x448.Key
		if _, err := io.ReadFull(rand.Reader, tempPriv[:]); err != nil {
			err1 = err
			return
		}
		x448.KeyGen(&tempPub, &tempPriv)

		if !x448.Shared(&ssvECC, &tempPriv, p.PubX) {
			err1 = errors.New("ECDH key exchange failed")
		}
	}()

	// 2. ML-KEM-1024 Encapsulation
	go func() {
		defer wg.Done()
		defer func() {
			if e := recover(); e != nil {
				err2 = e.(error) // panic to error
			}
		}()
		kemPub, err := mlkem1024.Scheme().UnmarshalBinaryPublicKey(p.PubKEM)
		if err != nil {
			err2 = err
			return
		}
		kemEnc, ssvKEM, err2 = mlkem1024.Scheme().Encapsulate(kemPub)
	}()

	// wait for all encryptions to finish
	wg.Wait()
	if err1 != nil {
		return nil, err1
	}
	if err2 != nil {
		return nil, err2
	}

	// 3. Hybrid KDF & Encryption
	sharedSecret := make([]byte, 0, len(ssvECC)+len(ssvKEM))
	sharedSecret = append(sharedSecret, ssvECC[:]...)
	sharedSecret = append(sharedSecret, ssvKEM...)
	defer sclear(sharedSecret)

	gcmKey, err := Genkey(sharedSecret, "KEYGEN_PQC1_ENCRYPT", 32)
	defer sclear(gcmKey)
	if err != nil {
		return nil, err
	}
	em := new(SymMaster)
	em.Init("gcm1", gcmKey)
	enc, err := em.EnBin(data)
	if err != nil {
		return nil, err
	}

	// [Temp X448 56B][Temp KEM 1568B][CipherText][Tag 16B]
	out := make([]byte, 0, 56+1568+len(enc))
	out = append(out, tempPub[:]...)
	out = append(out, kemEnc...)
	out = append(out, enc...)
	return out, nil
}

func (p *PQC1) Decrypt(data []byte) ([]byte, error) {
	if p.mask == nil {
		p.mask = GetMasker(-1)
	}
	if len(data) < 56+1568+16 {
		return nil, errors.New("data too short")
	}

	// 1. Seperate data
	tempPub := data[:56]
	kemEnc := data[56:1624]
	enc := data[1624:]

	var wg sync.WaitGroup
	wg.Add(2)

	// local variables
	var err1, err2 error
	var ssvECC x448.Key
	var ssvKEM []byte
	defer func() { sclear(ssvECC[:]) }()
	defer func() { sclear(ssvKEM) }()

	// 2-1. Shared Secret Value (ECC)
	go func() {
		defer wg.Done()
		defer func() {
			if e := recover(); e != nil {
				err1 = e.(error) // panic to error
			}
		}()
		var tempXKey x448.Key
		copy(tempXKey[:], tempPub)
		if !x448.Shared(&ssvECC, p.PrivX, &tempXKey) {
			err1 = errors.New("ECDH key exchange failed")
		}
	}()

	// 2-2. Shared Secret Value (KEM)
	go func() {
		defer wg.Done()
		defer func() {
			if e := recover(); e != nil {
				err2 = e.(error) // panic to error
			}
		}()

		privKEM, err := p.mask.XOR(p.PrivKEM)
		defer sclear(privKEM)
		if err != nil {
			err2 = err
			return
		}

		kemPriv, err := mlkem1024.Scheme().UnmarshalBinaryPrivateKey(privKEM)
		if err != nil {
			err2 = err
			return
		}
		ssvKEM, err2 = mlkem1024.Scheme().Decapsulate(kemPriv, kemEnc)
	}()

	// wait for all decryptions to finish
	wg.Wait()
	if err1 != nil {
		return nil, err1
	}
	if err2 != nil {
		return nil, err2
	}

	// 3. Hybrid KDF & Decryption
	sharedSecret := make([]byte, 0, len(ssvECC)+len(ssvKEM))
	sharedSecret = append(sharedSecret, ssvECC[:]...)
	sharedSecret = append(sharedSecret, ssvKEM...)
	defer sclear(sharedSecret)

	gcmKey, err := Genkey(sharedSecret, "KEYGEN_PQC1_ENCRYPT", 32)
	defer sclear(gcmKey)
	if err != nil {
		return nil, err
	}
	em := new(SymMaster)
	em.Init("gcm1", gcmKey)
	return em.DeBin(enc)
}

func (p *PQC1) Sign(data []byte) ([]byte, error) {
	if p.mask == nil {
		p.mask = GetMasker(-1)
	}
	var wg sync.WaitGroup
	wg.Add(2)

	// local variables
	var edSgn, mlSgn []byte
	var err1, err2 error

	// 1. ECC-Ed448 Sign
	go func() {
		defer wg.Done()
		defer func() {
			if e := recover(); e != nil {
				err1 = e.(error) // panic to error
			}
		}()
		edSgn = ed448.Sign(p.PrivEd, data, "")
	}()

	// 2. ML-DSA-87 Sign
	go func() {
		defer wg.Done()
		defer func() {
			if e := recover(); e != nil {
				err2 = e.(error) // panic to error
			}
		}()

		privDSA, err := p.mask.XOR(p.PrivDSA)
		defer sclear(privDSA)
		if err != nil {
			err2 = err
			return
		}

		dsaPriv, err := mldsa87.Scheme().UnmarshalBinaryPrivateKey(privDSA)
		if err != nil {
			err2 = err
			return
		}
		mlSgn = mldsa87.Scheme().Sign(dsaPriv, data, nil)
	}()

	// wait for all signatures to finish
	wg.Wait()
	if err1 != nil {
		return nil, err1
	}
	if err2 != nil {
		return nil, err2
	}

	// Join Signatures (114B + 4627B = 4741B)
	out := make([]byte, 0, len(edSgn)+len(mlSgn))
	out = append(out, edSgn...)
	out = append(out, mlSgn...)
	return out, nil
}

func (p *PQC1) Verify(data []byte, signature []byte) bool {
	if p.mask == nil {
		p.mask = GetMasker(-1)
	}
	if len(signature) != 4741 {
		return false
	}
	edSgn := signature[:114]
	mlSgn := signature[114:]

	var wg sync.WaitGroup
	wg.Add(2)

	// local variables
	var edOk, dsaOk bool

	// 1. ECC-Ed448 Verify
	go func() {
		defer wg.Done()
		defer func() {
			if e := recover(); e != nil {
				edOk = false // panic to error
			}
		}()
		edOk = ed448.Verify(p.PubEd, data, edSgn, "")
	}()

	// 2. ML-DSA-87 Verify
	go func() {
		defer wg.Done()
		defer func() {
			if e := recover(); e != nil {
				dsaOk = false // panic to error
			}
		}()
		dsaPub, err := mldsa87.Scheme().UnmarshalBinaryPublicKey(p.PubDSA)
		if err != nil {
			return
		}
		dsaOk = mldsa87.Scheme().Verify(dsaPub, data, mlSgn, nil)
	}()

	wg.Wait()
	return edOk && dsaOk // Both signatures must be valid
}
