// test794c : USAG-Lib opsec

package Opsec

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math/bits"
	"runtime"
	"sync"
	"sync/atomic"

	Bencrypt "github.com/k-atusa/USAG-Lib/Bencrypt"
)

// ========== Helper Functions ==========
var SCLEAR_BACK = func(b []byte) { clear(b) }

func sclear(data []byte) { SCLEAR_BACK(data); runtime.KeepAlive(data) }

func Crc32(data []byte) string {
	checksum := crc32.ChecksumIEEE(data)
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, checksum)
	return hex.EncodeToString(buf)
}

func PadLen(size int64) int64 {
	if size <= 0 {
		return 0
	}

	// 1. 0-16k: 4k*N
	if size <= 16384 {
		remainder := size % 4096
		if remainder == 0 {
			return 0
		}
		return 4096 - remainder
	}

	// get sup bit position
	bitLen := bits.Len64(uint64(size))
	var k int
	if bitLen <= 24 { // 16k-16m: K=2
		k = 2
	} else if bitLen <= 29 { // 16m-512m: K=3
		k = 3
	} else if bitLen <= 33 { // 512m-8g: K=4
		k = 4
	} else { // 8g+: K=5
		k = 5
	}

	// mask and ceiling
	shift := bitLen - k
	mask := (int64(1) << shift) - 1
	if size&mask == 0 { // on border size is not padded
		return 0
	}

	// return actual padding length
	aftersize := ((size >> shift) + 1) << shift
	return aftersize - size
}

func PadFile(f io.Writer, size int64) error {
	if size <= 0 {
		return nil
	}
	chunkSize := 128 * 1024         // 128 KiB
	rotationSize := 8 * 1024 * 1024 // 8 MiB

	// shared pools
	zeroBuf := make([]byte, chunkSize)
	bufPool := sync.Pool{
		New: func() any {
			return make([]byte, chunkSize)
		},
	}
	numWorkers := max(runtime.NumCPU(), 2)
	var stopFlag atomic.Bool
	stopFlag.Store(false)
	results := make(chan []byte, numWorkers*4)

	// writer
	var wg sync.WaitGroup
	errCh := make(chan error, 1)
	go func() {
		var writeErr error
		for buf := range results {
			if writeErr == nil {
				if _, err := f.Write(buf); err != nil {
					stopFlag.Store(true)
					writeErr = err
				}
			}
			bufPool.Put(buf) // return used buffer
		}
		errCh <- writeErr
	}()

	// Random generator
	blockerChan := make(chan bool, numWorkers)
	remainingSize := size
	for remainingSize > 0 {
		currentSegSize := min(remainingSize, int64(rotationSize))
		if stopFlag.Load() {
			break
		}

		wg.Add(1)
		blockerChan <- true
		go func(segSize int64) {
			defer wg.Done()
			defer func() { <-blockerChan }()
			key := Bencrypt.Random(48)
			block, _ := aes.NewCipher(key[16:48]) // AES-CTR CSPRNG
			stream := cipher.NewCTR(block, key[0:16])

			for i := int64(0); i < segSize; i += int64(chunkSize) {
				if stopFlag.Load() {
					return
				}
				currChunkSize := min(segSize-i, int64(chunkSize))

				fullBuf := bufPool.Get().([]byte)
				buf := fullBuf[:cap(fullBuf)][:currChunkSize]
				stream.XORKeyStream(buf, zeroBuf[:currChunkSize])
				results <- buf
			}
		}(currentSegSize)
		remainingSize -= currentSegSize
	}

	wg.Wait()
	close(blockerChan)
	close(results)
	return <-errCh
}

func EncodeInt(data uint64, size int) []byte {
	buf := make([]byte, size)
	switch size {
	case 1:
		buf[0] = byte(data)
	case 2:
		binary.LittleEndian.PutUint16(buf, uint16(data))
	case 4:
		binary.LittleEndian.PutUint32(buf, uint32(data))
	case 8:
		binary.LittleEndian.PutUint64(buf, data)
	}
	return buf
}

func DecodeInt(data []byte) uint64 {
	l := len(data)
	switch l {
	case 1:
		return uint64(data[0])
	case 2:
		return uint64(binary.LittleEndian.Uint16(data))
	case 4:
		return uint64(binary.LittleEndian.Uint32(data))
	case 8:
		return binary.LittleEndian.Uint64(data)
	default:
		return 0
	}
}

// Config Encoding, keysize max 127, datasize max 65535
func EncodeCfg(data map[string][]byte) ([]byte, error) {
	var buf bytes.Buffer
	for key, val := range data {
		keyBytes := []byte(key)
		keyLen := len(keyBytes)
		dataLen := len(val)
		if keyLen > 127 {
			return nil, errors.New("key length too long")
		}
		if dataLen > 65535 {
			return nil, errors.New("data size too big")
		}

		if dataLen > 255 {
			buf.WriteByte(byte(keyLen + 128))
			buf.Write(keyBytes)
			buf.Write(EncodeInt(uint64(dataLen), 2))
		} else {
			buf.WriteByte(byte(keyLen))
			buf.Write(keyBytes)
			buf.WriteByte(byte(dataLen))
		}
		buf.Write(val)
	}
	return buf.Bytes(), nil
}

// Config Decoding, [keyLen 1B][key][dataLen 1B/2B][data]
func DecodeCfg(data []byte) map[string][]byte {
	result := make(map[string][]byte)
	totalLen := len(data)
	offset := 0
	for offset < totalLen {
		// Get Key
		keyLen := int(data[offset])
		offset++
		isLongData := false
		if keyLen > 127 {
			keyLen -= 128
			isLongData = true
		}
		key := string(data[offset : offset+keyLen])
		offset += keyLen

		// Get Data
		var dataLen int
		if isLongData {
			dataLen = int(DecodeInt(data[offset : offset+2]))
			offset += 2
		} else {
			dataLen = int(data[offset])
			offset++
		}
		result[key] = data[offset : offset+dataLen]
		offset += dataLen
	}
	return result
}

// Opsec header handler
type Opsec struct {
	// Outer Layer
	Msg         string // non-secured message
	MsgInfo     []byte // additional info (for RSA-mode)
	headAlgo    string // header algorithm
	salt        []byte // salt
	encHeadData []byte // encrypted header data

	// Inner Layer
	Smsg     string // secured message
	SmsgInfo []byte // private additional info (timestamp, ID, etc.)
	sign     []byte // signature

	BodyAlgo string // body algorithm
	BodyKey  []byte // body key
	BodySize int64  // full body size, flag for bodyKey generation
	BodyInfo []byte // additional info for body (packing info, etc.)

	SaltLen int
}

func (o *Opsec) Clear() {
	sclear(o.salt)
	sclear(o.encHeadData)
	sclear(o.MsgInfo)
	sclear(o.SmsgInfo)
	sclear(o.sign)
	sclear(o.BodyKey)
	sclear(o.BodyInfo)
	o.Init()
}

// set initial values
func (o *Opsec) Init() {
	o.Msg = ""
	o.MsgInfo = []byte{}
	o.headAlgo = ""
	o.salt = []byte{}
	o.encHeadData = []byte{}

	o.Smsg = ""
	o.SmsgInfo = []byte{}
	o.sign = []byte{}

	o.BodyAlgo = ""
	o.BodyKey = []byte{}
	o.BodySize = -1
	o.BodyInfo = []byte{}

	o.SaltLen = 32
}

// Read opsec header from stream, set cut to 0 to read all
func (o *Opsec) Read(r io.Reader, cut int) ([]byte, error) {
	c := 0
	buf4 := make([]byte, 4)
	buf2 := make([]byte, 2)
	buf124 := make([]byte, 124)
	for {
		_, err := io.ReadFull(r, buf4)
		if err != nil { // EOF or Error
			return nil, nil
		}
		c += 4

		if string(buf4) == "YAS2" { // magic number
			_, err := io.ReadFull(r, buf2)
			if err != nil {
				return nil, err
			}
			size := int(DecodeInt(buf2))
			if size == 65535 {
				_, err := io.ReadFull(r, buf2)
				if err != nil {
					return nil, err
				}
				size += int(DecodeInt(buf2))
			}

			// Read payload
			payload := make([]byte, size)
			_, err = io.ReadFull(r, payload)
			if err != nil {
				return nil, err
			}
			return payload, nil

		} else { // skip
			_, err := io.ReadFull(r, buf124)
			if err != nil {
				return nil, nil
			}
			c += 124
		}
		if cut > 0 && c > cut {
			return nil, nil
		}
	}
}

// Write opsec header to stream
func (o *Opsec) Write(w io.Writer, head []byte) error {
	if _, err := w.Write([]byte("YAS2")); err != nil {
		return err
	}
	size := len(head)
	if size < 65535 {
		if _, err := w.Write(EncodeInt(uint64(size), 2)); err != nil {
			return err
		}
	} else if size <= 65535*2 {
		if _, err := w.Write(EncodeInt(65535, 2)); err != nil {
			return err
		}
		if _, err := w.Write(EncodeInt(uint64(size-65535), 2)); err != nil {
			return err
		}
	} else {
		return errors.New("data size too big")
	}
	if _, err := w.Write(head); err != nil {
		return err
	}
	return nil
}

func (o *Opsec) wrapEncHead() ([]byte, error) {
	cfg := make(map[string][]byte)
	if o.Smsg != "" {
		cfg["smsg"] = []byte(o.Smsg)
	}
	if len(o.SmsgInfo) > 0 {
		cfg["sinf"] = o.SmsgInfo
	}
	if len(o.sign) > 0 {
		cfg["sgn"] = o.sign
	}
	if o.BodyAlgo != "" {
		cfg["bal"] = []byte(o.BodyAlgo)
	}
	if len(o.BodyKey) > 0 {
		cfg["bkey"] = o.BodyKey
	}
	if o.BodySize >= 0 {
		var szBytes []byte
		if o.BodySize < 65536 {
			szBytes = EncodeInt(uint64(o.BodySize), 2)
		} else if o.BodySize < 4294967296 {
			szBytes = EncodeInt(uint64(o.BodySize), 4)
		} else {
			szBytes = EncodeInt(uint64(o.BodySize), 8)
		}
		cfg["bsz"] = szBytes
	}
	if len(o.BodyInfo) > 0 {
		cfg["binf"] = o.BodyInfo
	}
	return EncodeCfg(cfg)
}

func (o *Opsec) unwrapEncHead(data []byte) {
	cfg := DecodeCfg(data)
	if v, ok := cfg["smsg"]; ok {
		o.Smsg = string(v)
	}
	if v, ok := cfg["sinf"]; ok {
		o.SmsgInfo = v
	}
	if v, ok := cfg["sgn"]; ok {
		o.sign = v
	}
	if v, ok := cfg["bal"]; ok {
		o.BodyAlgo = string(v)
	}
	if v, ok := cfg["bkey"]; ok {
		o.BodyKey = v
	}
	if v, ok := cfg["bsz"]; ok {
		o.BodySize = int64(DecodeInt(v))
	}
	if v, ok := cfg["binf"]; ok {
		o.BodyInfo = v
	}
}

// Encrypt with password
func (o *Opsec) Encpw(method string, pw []byte, kf []byte) ([]byte, error) {
	// generate random parameters
	if o.SaltLen <= 0 {
		o.SaltLen = 32
	}
	o.headAlgo = method
	o.salt = Bencrypt.Random(o.SaltLen)
	if o.BodySize >= 0 {
		o.BodyKey = Bencrypt.Random(32)
	}

	// Combine pw + kf
	combinedPw := make([]byte, 0, len(pw)+len(kf))
	combinedPw = append(combinedPw, pw...)
	combinedPw = append(combinedPw, kf...)
	defer sclear(combinedPw)

	// KDF via HashMaster
	hm := new(Bencrypt.HashMaster)
	if err := hm.Init(method, 0, 0); err != nil {
		return nil, err
	}
	_, hkey, err := hm.KDF(combinedPw, o.salt)
	defer sclear(hkey)
	if err != nil {
		return nil, err
	}

	// Encrypt header
	headData, err := o.wrapEncHead()
	defer sclear(headData)
	if err != nil {
		return nil, err
	}
	sm := new(Bencrypt.SymMaster)
	if err := sm.Init("gcm1", hkey); err != nil {
		return nil, err
	}
	o.encHeadData, err = sm.EnBin(headData)
	if err != nil {
		return nil, err
	}

	// Wrap outer header
	cfg := make(map[string][]byte)
	if o.Msg != "" {
		cfg["msg"] = []byte(o.Msg)
	}
	if len(o.MsgInfo) > 0 {
		cfg["minf"] = o.MsgInfo
	}
	cfg["hal"] = []byte(o.headAlgo)
	cfg["salt"] = o.salt
	cfg["ehd"] = o.encHeadData
	return EncodeCfg(cfg)
}

// Encrypt with public key, sign if private key is not nil
func (o *Opsec) Encpub(method string, peerPub []byte, myPri []byte) ([]byte, error) {
	o.headAlgo = method
	if o.BodySize >= 0 {
		o.BodyKey = Bencrypt.Random(32)
	}

	// Sign if private key is provided
	if myPri != nil {
		amSign := new(Bencrypt.AsymMaster)
		if err := amSign.Init(method); err != nil {
			return nil, err
		}
		if err := amSign.Loadkey(nil, myPri); err != nil {
			return nil, err
		}

		signTgt := make([]byte, 0)
		signTgt = append(signTgt, []byte(method)...)
		signTgt = append(signTgt, 0)
		signTgt = append(signTgt, peerPub...)
		signTgt = append(signTgt, 0)
		signTgt = append(signTgt, []byte(o.Smsg)...)
		signTgt = append(signTgt, 0)
		signTgt = append(signTgt, o.SmsgInfo...)
		signTgt = append(signTgt, 0)
		defer sclear(signTgt)

		var err error
		o.sign, err = amSign.Sign(signTgt)
		if err != nil {
			return nil, err
		}
	}

	// Encrypt header
	amEncrypt := new(Bencrypt.AsymMaster)
	if err := amEncrypt.Init(method); err != nil {
		return nil, err
	}
	if err := amEncrypt.Loadkey(peerPub, nil); err != nil {
		return nil, err
	}

	headData, err := o.wrapEncHead()
	defer sclear(headData)
	if err != nil {
		return nil, err
	}

	o.encHeadData, err = amEncrypt.Encrypt(headData)
	if err != nil {
		return nil, err
	}

	// Wrap outer header
	cfg := make(map[string][]byte)
	if o.Msg != "" {
		cfg["msg"] = []byte(o.Msg)
	}
	if len(o.MsgInfo) > 0 {
		cfg["minf"] = o.MsgInfo
	}
	cfg["hal"] = []byte(o.headAlgo)
	cfg["ehd"] = o.encHeadData
	return EncodeCfg(cfg)
}

// Load outer layer of header
func (o *Opsec) View(data []byte) {
	o.Init()
	cfg := DecodeCfg(data)
	if v, ok := cfg["msg"]; ok {
		o.Msg = string(v)
	}
	if v, ok := cfg["minf"]; ok {
		o.MsgInfo = v
	}
	if v, ok := cfg["hal"]; ok {
		o.headAlgo = string(v)
	}
	if v, ok := cfg["salt"]; ok {
		o.salt = v
	}
	if v, ok := cfg["ehd"]; ok {
		o.encHeadData = v
	}
}

// Decrypt with password
func (o *Opsec) Decpw(pw []byte, kf []byte) error {
	if o.headAlgo == "" {
		return errors.New("Opsec not initialized or invalid data")
	}
	combinedPw := make([]byte, 0, len(pw)+len(kf))
	combinedPw = append(combinedPw, pw...)
	combinedPw = append(combinedPw, kf...)
	defer sclear(combinedPw)

	// KDF via HashMaster
	hm := new(Bencrypt.HashMaster)
	if err := hm.Init(o.headAlgo, 0, 0); err != nil {
		return err
	}
	_, hkey, err := hm.KDF(combinedPw, o.salt)
	defer sclear(hkey)
	if err != nil {
		return err
	}

	// Decrypt header (verification is handled by symmaster GCM tag checking)
	sm := new(Bencrypt.SymMaster)
	if err := sm.Init("gcm1", hkey); err != nil {
		return err
	}
	decryptedHead, err := sm.DeBin(o.encHeadData)
	if err != nil {
		return fmt.Errorf("AES decryption failed: %w", err)
	}
	o.unwrapEncHead(decryptedHead)
	return nil
}

// Decrypt with private key, verify if public key is not nil
func (o *Opsec) Decpub(myPri []byte, myPub []byte, peerPub []byte) error {
	if o.headAlgo == "" {
		return errors.New("Opsec not initialized or invalid data")
	}

	// Init AsymMaster
	am := new(Bencrypt.AsymMaster)
	if err := am.Init(o.headAlgo); err != nil {
		return err
	}
	if err := am.Loadkey(nil, myPri); err != nil {
		return err
	}

	// Decrypt header
	var decryptedHead []byte
	var err error

	decryptedHead, err = am.Decrypt(o.encHeadData)
	if err != nil {
		return fmt.Errorf("Asymmetric decryption failed: %w", err)
	}
	o.unwrapEncHead(decryptedHead)

	// Verify if public keys are provided
	if myPub == nil && peerPub == nil {
		return nil
	}
	if myPub == nil || peerPub == nil {
		if len(o.sign) > 0 {
			return errors.New("both myPub and peerPub should be provided to verify sign")
		}
		return nil
	}

	amVerify := new(Bencrypt.AsymMaster)
	if err := amVerify.Init(o.headAlgo); err != nil {
		return err
	}
	if err := amVerify.Loadkey(peerPub, nil); err != nil {
		return err
	}

	signTgt := make([]byte, 0)
	signTgt = append(signTgt, []byte(o.headAlgo)...)
	signTgt = append(signTgt, 0)
	signTgt = append(signTgt, myPub...)
	signTgt = append(signTgt, 0)
	signTgt = append(signTgt, []byte(o.Smsg)...)
	signTgt = append(signTgt, 0)
	signTgt = append(signTgt, o.SmsgInfo...)
	signTgt = append(signTgt, 0)

	if !amVerify.Verify(signTgt, o.sign) {
		return errors.New("signature verification failed")
	}
	return nil
}
