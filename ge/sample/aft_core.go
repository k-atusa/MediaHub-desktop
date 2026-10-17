// test798a : project USAG AFT-desktop core
package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"

	"github.com/k-atusa/USAG-Lib/Bencrypt"
	"github.com/k-atusa/USAG-Lib/Icons"
	"github.com/k-atusa/USAG-Lib/Opsec"
)

const AFT_VERSION string = "2026 @k-atusa [USAG] AFT v1.5.0"
const METHOD_HASH string = "sha3"
const METHOD_SYM string = "gcmx1"
const LIMIT_MEM int64 = 512 * 1048576

var SCLEAR_BACK = func(b []byte) { clear(b) }

func sclear(data []byte) { SCLEAR_BACK(data); runtime.KeepAlive(data) }

// AFT Vault
type AVault struct {
	Path  string
	DoPad bool
	Mask  *Bencrypt.Masker

	AlgoType string // arg2low, arg2st
	Ext      string // webp, png, bin
	VaultKey []byte // vault masterkey (masked)

	// name rule: *, */, */*
	TreeView map[string][]string // treeview with plain name
	PtoCtbl  map[string]string   // plain name -> cipher name
	CtoPtbl  map[string]string   // cipher name -> plain name
}

func (a *AVault) prehead() []byte {
	var ico []byte
	switch a.Ext {
	case "webp":
		ico = Icons.ZipWebp
	case "png":
		ico = Icons.ZipPng
	default:
		return nil
	}
	return append(ico, make([]byte, 128-len(ico)%128)...)
}

func (a *AVault) qread(path string, pw []byte, kf []byte) (data []byte, msg string, smsgi []byte, err error) {
	// open file
	f, err := os.Open(path)
	if err != nil {
		return data, msg, smsgi, err
	}
	defer f.Close()

	// read and decrypt header
	ops := new(Opsec.Opsec)
	ops.Init()
	defer ops.Clear()
	h, err := ops.Read(f, 0)
	if err != nil {
		return data, msg, smsgi, err
	}
	ops.View(h)
	msg = ops.Msg
	err = ops.Decpw(pw, kf) // plain pw kf
	smsgi = bytes.Clone(ops.SmsgInfo)
	if err != nil {
		return data, msg, smsgi, err
	}
	if ops.BodySize <= 0 { // only header, no body
		return data, msg, smsgi, nil
	}

	// decrypt body
	sm := new(Bencrypt.SymMaster)
	defer func() { sclear(sm.Key) }()
	if err := sm.Init(ops.BodyAlgo, ops.BodyKey); err != nil {
		return data, msg, smsgi, err
	}
	buf := bytes.NewBuffer(make([]byte, 0, ops.BodySize))
	if err := sm.DeFile(f, ops.BodySize, buf); err != nil {
		return data, msg, smsgi, err
	}
	data = buf.Bytes()
	return data, msg, smsgi, nil
}

func (a *AVault) hwrite(msg string, smsgi []byte, path string, pw []byte, kf []byte) error {
	// encrypt header
	ops := new(Opsec.Opsec)
	ops.Init()
	defer ops.Clear()
	ops.Msg = msg
	ops.SmsgInfo = smsgi
	header, err := ops.Encpw(a.AlgoType, pw, kf) // plain pw kf
	if err != nil {
		return err
	}

	// write header to file
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var writed int64 = 0
	tb := a.prehead()
	writed += int64(len(tb))
	if _, err := f.Write(tb); err != nil {
		return err
	}
	writed += int64(len(header)) + 6 // opsec magic
	if len(header) >= 65535 {
		writed += 2
	}
	if err := ops.Write(f, header); err != nil {
		return err
	}
	if a.DoPad {
		padLen := Opsec.PadLen(writed)
		err = Opsec.PadFile(f, padLen)
		if err != nil {
			return err
		}
		writed += padLen
	}
	return nil
}

func (a *AVault) qwrite(data []byte, path string, pw []byte) error {
	// prepare worker
	sm := new(Bencrypt.SymMaster)
	defer func() { sclear(sm.Key) }()
	if err := sm.Init(METHOD_SYM, make([]byte, 32)); err != nil {
		return err
	}

	// encrypt header
	ops := new(Opsec.Opsec)
	ops.Init()
	defer ops.Clear()
	ops.BodySize = sm.AfterSize(int64(len(data)))
	ops.BodyAlgo = METHOD_SYM
	header, err := ops.Encpw(METHOD_HASH, pw, nil) // plain pw
	if err == nil {
		err = sm.Init(sm.Algo, ops.BodyKey)
	}
	if err != nil {
		return err
	}

	// write header and body to file
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var writed int64 = 0
	tb := a.prehead()
	writed += int64(len(tb))
	if _, err := f.Write(tb); err != nil {
		return err
	}
	writed += int64(len(header)) + 6 // opsec magic
	if len(header) >= 65535 {
		writed += 2
	}
	if err := ops.Write(f, header); err != nil {
		return err
	}

	writed += ops.BodySize
	if err := sm.EnFile(bytes.NewBuffer(data), int64(len(data)), f); err != nil {
		return err
	}
	if a.DoPad {
		padLen := Opsec.PadLen(writed)
		err = Opsec.PadFile(f, padLen)
		if err != nil {
			return err
		}
		writed += padLen
	}
	return nil
}

// get encrypted name of file
func (a *AVault) hexname(name string) string {
	// check exists
	cipher, exists := a.PtoCtbl[name]
	if !exists {
		// split name
		parent, child := "", name
		if idx := strings.Index(name, "/"); idx != -1 {
			parent = name[:idx+1]
			child = name[idx+1:]
		}

		// make new cipher name, update tables
		for {
			cChild := hex.EncodeToString(Bencrypt.Random(12)) + "." + a.Ext
			if parent == "" {
				cipher = cChild
			} else {
				cipher = a.PtoCtbl[parent] + cChild
			}
			if _, collision := a.CtoPtbl[cipher]; !collision {
				break
			}
		}
		a.PtoCtbl[name] = cipher
		a.CtoPtbl[cipher] = name

		// update treeview
		if _, ok := a.TreeView[parent]; !ok {
			a.TreeView[parent] = make([]string, 0)
		}
		a.TreeView[parent] = append(a.TreeView[parent], child)
		sort.Strings(a.TreeView[parent])
	}
	return cipher
}

// load vault from disk
func (a *AVault) Load(pw []byte, kf []byte) (string, error) {
	// 1. find account.*, name.* files
	files, err := os.ReadDir(a.Path)
	if err != nil {
		return "", err
	}
	accPath, nmPath := "", ""
	for _, f := range files {
		if !f.IsDir() && strings.HasPrefix(f.Name(), "account.") && !strings.HasSuffix(f.Name(), ".old") {
			accPath = filepath.Join(a.Path, f.Name())
		}
		if !f.IsDir() && strings.HasPrefix(f.Name(), "name.") && !strings.HasSuffix(f.Name(), ".old") {
			nmPath = filepath.Join(a.Path, f.Name())
		}
	}
	if accPath == "" || nmPath == "" {
		return "", errors.New("cannot find data files")
	}

	// 2. load account file, set (AlgoType, Ext, VaultKey)
	_, msg, smsgi, err := a.qread(accPath, pw, kf) // plain pw kf
	defer sclear(smsgi)
	if err != nil {
		return msg, err
	}
	a.AlgoType, a.Ext = strings.Trim(string(smsgi[0:16]), " "), strings.Trim(string(smsgi[16:32]), " ")
	a.VaultKey, err = a.Mask.XOR(smsgi[32:]) // save VaultKey as masked
	if err != nil {
		return msg, err
	}

	// 3. load name file
	data, _, _, err := a.qread(nmPath, smsgi[32:], nil)
	if err != nil {
		return msg, err
	}
	nmLines := strings.Split(string(data), "\n")
	data = nil
	a.PtoCtbl = make(map[string]string)
	a.CtoPtbl = make(map[string]string)
	for i := 0; i < len(nmLines)-1; i += 2 {
		if i+1 < len(nmLines) {
			a.PtoCtbl[nmLines[i]] = nmLines[i+1]
			a.CtoPtbl[nmLines[i+1]] = nmLines[i]
		}
	}

	// 4. make name tree
	a.TreeView = make(map[string][]string)
	a.TreeView[""] = make([]string, 0)
	for plain := range a.PtoCtbl {
		idx := strings.IndexAny(plain, "/")
		if idx == -1 { // golbal file
			a.TreeView[""] = append(a.TreeView[""], plain)
		} else { // folder or file in folder
			parent, child := plain[:idx+1], plain[idx+1:]
			if _, ok := a.TreeView[parent]; !ok { // add parent folder
				a.TreeView[parent] = make([]string, 0)
			}
			if child == "" { // add parent folder to root
				a.TreeView[""] = append(a.TreeView[""], parent)
			} else { // add child file
				a.TreeView[parent] = append(a.TreeView[parent], child)
			}
		}
	}
	for parent := range a.TreeView {
		sort.Strings(a.TreeView[parent])
	}
	return msg, nil
}

// store name table to disk
func (a *AVault) StoreName() error {
	// 1. make name list binary
	nameList := make([]string, 2*len(a.PtoCtbl))
	idx := 0
	for plain, cipher := range a.PtoCtbl {
		nameList[idx] = plain
		nameList[idx+1] = cipher
		idx += 2
	}
	data := []byte(strings.Join(nameList, "\n"))
	nameList = nil

	// 2. write
	path := filepath.Join(a.Path, "name."+a.Ext)
	os.Rename(path, path+".old")
	key, err := a.Mask.XOR(a.VaultKey) // restore VaultKey
	defer sclear(key)
	if err != nil {
		return err
	}
	return a.qwrite(data, path, key)
}

// store account to disk, !!! VaultKey is not changed !!!
func (a *AVault) StoreAccount(pw []byte, kf []byte, msg string) error {
	path := filepath.Join(a.Path, "account."+a.Ext)
	os.Rename(path, path+".old")
	key, err := a.Mask.XOR(a.VaultKey) // restore VaultKey
	defer sclear(key)
	if err != nil {
		return err
	}
	if len(a.AlgoType) > 16 || len(a.Ext) > 16 {
		return errors.New("invalid AlgoType or Ext")
	}
	smsgi := make([]byte, 0, 32+len(key))
	defer func() { sclear(smsgi) }()
	smsgi = append(smsgi, []byte(a.AlgoType)...)
	for i := 0; i < 16-len(a.AlgoType); i++ {
		smsgi = append(smsgi, ' ')
	}
	smsgi = append(smsgi, []byte(a.Ext)...)
	for i := 0; i < 16-len(a.Ext); i++ {
		smsgi = append(smsgi, ' ')
	}
	smsgi = append(smsgi, key...)
	return a.hwrite(msg, smsgi, path, pw, kf) // plain pw kf
}

// add file or folder to vault
func (a *AVault) Add(path string, dirname string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	// add file, assume dirname exists
	if !info.IsDir() {
		if info.Size() < LIMIT_MEM {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			return a.Write(dirname+info.Name(), data)
		} else {
			cipher := a.hexname(dirname + info.Name())
			err := a.Bypass(path, filepath.Join(a.Path, cipher), true)
			if err != nil {
				return err
			}
			return a.StoreName()
		}
	}

	// add folder (single layer)
	if _, ok := a.PtoCtbl[info.Name()+"/"]; ok {
		return errors.New("folder already exists")
	}
	cParent := ""
	for {
		cParent = hex.EncodeToString(Bencrypt.Random(12)) + "/"
		if _, collision := a.CtoPtbl[cParent]; !collision {
			break
		}
	}
	os.Mkdir(filepath.Join(a.Path, cParent), 0755)
	a.PtoCtbl[info.Name()+"/"] = cParent
	a.CtoPtbl[cParent] = info.Name() + "/"
	a.TreeView[info.Name()+"/"] = make([]string, 0)
	a.TreeView[""] = append(a.TreeView[""], info.Name()+"/")
	sort.Strings(a.TreeView[""])

	files, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return a.StoreName() // store empty folder
	}
	for _, file := range files {
		if !file.IsDir() { // add only first layer
			if err := a.Add(filepath.Join(path, file.Name()), info.Name()+"/"); err != nil {
				return err
			}
		}
	}
	return nil
}

// delete file or folder from vault
func (a *AVault) Del(name string) error {
	isFolder := strings.HasSuffix(name, "/")

	// delete actual files, update tables
	for plain, cipher := range a.PtoCtbl {
		if plain == name || (isFolder && strings.HasPrefix(plain, name)) {
			os.RemoveAll(filepath.Join(a.Path, cipher))
			delete(a.CtoPtbl, cipher)
			delete(a.PtoCtbl, plain)
		}
	}

	// update treeview
	if isFolder {
		list := a.TreeView[""]
		for i, v := range list {
			if v == name {
				a.TreeView[""] = append(list[:i], list[i+1:]...)
				break
			}
		}
		delete(a.TreeView, name)

	} else {
		parent, child := "", name
		if idx := strings.Index(name, "/"); idx != -1 {
			parent, child = name[:idx+1], name[idx+1:]
		}
		list := a.TreeView[parent]
		for i, v := range list {
			if v == child {
				a.TreeView[parent] = append(list[:i], list[i+1:]...)
				break
			}
		}
	}
	return a.StoreName()
}

// rename file or folder in vault
func (a *AVault) Rename(src string, dst string) error {
	// check source
	if _, ok := a.PtoCtbl[src]; !ok {
		return errors.New("source not found")
	}
	if _, ok := a.PtoCtbl[dst]; ok {
		return errors.New("destination already exists")
	}
	isFolder := strings.HasSuffix(src, "/")
	if isFolder && !strings.HasSuffix(dst, "/") {
		return errors.New("invalid destination for folder")
	}
	idx0 := strings.Index(src, "/")
	idx1 := strings.Index(dst, "/")
	if !isFolder {
		dir0 := ""
		if idx0 != -1 {
			dir0 = src[:idx0+1]
		}
		dir1 := ""
		if idx1 != -1 {
			dir1 = dst[:idx1+1]
		}
		if dir0 != dir1 {
			return errors.New("invalid destination for file")
		}
	}

	// rename tables
	toDelete := make([]string, 0)
	toAdd := make([]string, 0)
	for pName, cName := range a.PtoCtbl {
		if pName == src || (isFolder && strings.HasPrefix(pName, src)) {
			updatedPName := dst + pName[len(src):]
			toDelete = append(toDelete, pName, cName)
			toAdd = append(toAdd, updatedPName, cName)
		}
	}
	for i := 0; i < len(toDelete); i += 2 {
		delete(a.PtoCtbl, toDelete[i])
		delete(a.CtoPtbl, toDelete[i+1])
	}
	for i := 0; i < len(toAdd); i += 2 {
		a.PtoCtbl[toAdd[i]] = toAdd[i+1]
		a.CtoPtbl[toAdd[i+1]] = toAdd[i]
	}
	toDelete, toAdd = nil, nil

	// update treeview
	if isFolder {
		idx := slices.Index(a.TreeView[""], src)
		if idx != -1 {
			a.TreeView[""][idx] = dst
			sort.Strings(a.TreeView[""])
		}
		a.TreeView[dst] = a.TreeView[src]
		delete(a.TreeView, src)

	} else {
		parent, oldChild := "", src
		if idx0 != -1 {
			parent, oldChild = src[:idx0+1], src[idx0+1:]
		}
		newChild := dst
		if idx1 != -1 {
			newChild = dst[idx1+1:]
		}
		idx := slices.Index(a.TreeView[parent], oldChild)
		if idx != -1 {
			a.TreeView[parent][idx] = newChild
			sort.Strings(a.TreeView[parent])
		}
	}
	return a.StoreName()
}

// read file from vault
func (a *AVault) Read(name string) ([]byte, error) {
	// find cipher name, read file
	cipher, ok := a.PtoCtbl[name]
	if !ok {
		return nil, errors.New("file not found in vault")
	}
	path := filepath.Join(a.Path, cipher)
	key, err := a.Mask.XOR(a.VaultKey)
	defer sclear(key)
	if err != nil {
		return nil, err
	}
	data, _, _, err := a.qread(path, key, nil)
	return data, err
}

// write file to vault, make new if not exists
func (a *AVault) Write(name string, data []byte) error {
	path := filepath.Join(a.Path, a.hexname(name))
	key, err := a.Mask.XOR(a.VaultKey)
	defer sclear(key)
	if err != nil {
		return err
	}
	if err := a.qwrite(data, path, key); err != nil {
		return err
	}
	return a.StoreName()
}

// encrypt or decrypt big file
func (a *AVault) Bypass(src string, dst string, isEnc bool) error {
	// open files
	srcf, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcf.Close()
	dstf, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstf.Close()

	// prepare worker
	ops := new(Opsec.Opsec)
	ops.Init()
	defer ops.Clear()
	sm := new(Bencrypt.SymMaster)
	defer func() { sclear(sm.Key) }()
	if err := sm.Init(METHOD_SYM, make([]byte, 32)); err != nil {
		return err
	}

	// prepare key
	key, err := a.Mask.XOR(a.VaultKey)
	defer sclear(key)
	if err != nil {
		return err
	}

	if isEnc {
		// make header
		info, err := srcf.Stat()
		if err != nil {
			return err
		}
		ops.BodySize = sm.AfterSize(info.Size())
		ops.BodyAlgo = METHOD_SYM
		header, err := ops.Encpw(METHOD_HASH, key, nil)
		if err == nil {
			err = sm.Init(sm.Algo, ops.BodyKey)
		}
		if err != nil {
			return err
		}

		// write header
		var writed int64 = 0
		tb := a.prehead()
		writed += int64(len(tb))
		if _, err := dstf.Write(tb); err != nil {
			return err
		}
		writed += int64(len(header)) + 6 // opsec magic
		if len(header) >= 65535 {
			writed += 2
		}
		if err := ops.Write(dstf, header); err != nil {
			return err
		}

		// encrypt and pad
		writed += ops.BodySize
		if err := sm.EnFile(srcf, info.Size(), dstf); err != nil {
			return err
		}
		if a.DoPad {
			padLen := Opsec.PadLen(writed)
			err = Opsec.PadFile(dstf, padLen)
			if err != nil {
				return err
			}
			writed += padLen
		}

	} else {
		// read and decrypt header
		h, err := ops.Read(srcf, 0)
		if err != nil {
			return err
		}
		ops.View(h)
		err = ops.Decpw(key, nil)
		if err != nil {
			return err
		}

		// decrypt body
		if err := sm.Init(ops.BodyAlgo, ops.BodyKey); err != nil {
			return err
		}
		if err := sm.DeFile(srcf, ops.BodySize, dstf); err != nil {
			return err
		}
	}
	return nil
}

// sync vault with file system
func (a *AVault) Trim() (int, error) {
	count := 0

	// delete registered but not exists
	for plain, cipher := range a.PtoCtbl {
		fPath := filepath.Join(a.Path, cipher)
		if _, err := os.Stat(fPath); os.IsNotExist(err) {
			delete(a.PtoCtbl, plain)
			delete(a.CtoPtbl, cipher)
			count++
		}
	}

	// delete unregistered but exists
	err := filepath.Walk(a.Path, func(path string, info os.FileInfo, err error) error {
		if err != nil || path == a.Path {
			return nil
		}
		rel, _ := filepath.Rel(a.Path, path)
		rel = filepath.ToSlash(rel)

		// skip account and name files
		if strings.HasPrefix(rel, "account.") || strings.HasPrefix(rel, "name.") {
			return nil
		}

		// make lookup key
		key := rel
		if info.IsDir() {
			key += "/"
		}

		// delete if not exists in table
		if _, ok := a.CtoPtbl[key]; !ok {
			os.RemoveAll(path)
			count++
			if info.IsDir() {
				return filepath.SkipDir
			}
		}
		return nil
	})
	if err != nil {
		return count, err
	}

	// rebuild treeview
	a.TreeView = make(map[string][]string)
	a.TreeView[""] = make([]string, 0)
	for plain := range a.PtoCtbl {
		idx := strings.Index(plain, "/")
		if idx == -1 { // global files
			a.TreeView[""] = append(a.TreeView[""], plain)
		} else { // folders and files in folders
			parent, child := plain[:idx+1], plain[idx+1:]
			if _, ok := a.TreeView[parent]; !ok { // add parent folder
				a.TreeView[parent] = make([]string, 0)
			}
			if child == "" { // add parent folder to root
				a.TreeView[""] = append(a.TreeView[""], parent)
			} else { // add child file
				a.TreeView[parent] = append(a.TreeView[parent], child)
			}
		}
	}

	// sort and save
	for k := range a.TreeView {
		sort.Strings(a.TreeView[k])
	}
	return count, a.StoreName()
}

// re-encrypt file with new masterkey
func (a *AVault) ReCrypt(cipher string, oldKey []byte, newKey []byte) error {
	path := filepath.Join(a.Path, cipher)
	srcf, err := os.Open(path)
	if err != nil {
		return err
	}
	defer srcf.Close()

	// read Opsec header
	ops := new(Opsec.Opsec)
	ops.Init()
	defer ops.Clear()
	h, err := ops.Read(srcf, 0)
	if err != nil {
		return err
	}
	ops.View(h)

	// decode oldkey and decrypt
	oKey, err := a.Mask.XOR(oldKey)
	defer sclear(oKey)
	if err != nil {
		return err
	}
	if err := ops.Decpw(oKey, nil); err != nil {
		return err
	}

	// copy bodykey, get GCMX1 plainsize
	oldBodyKey := append([]byte(nil), ops.BodyKey...)
	defer sclear(oldBodyKey)
	bodySize := ops.BodySize
	cSz := bodySize - 12
	plainSize := (cSz / 1048592) * 1048576
	if rem := cSz % 1048592; rem > 0 {
		plainSize += rem - 16
	}

	// decode newkey and encrypt
	nKey, err := a.Mask.XOR(newKey)
	defer sclear(nKey)
	if err != nil {
		return err
	}
	header, err := ops.Encpw(METHOD_HASH, nKey, nil)
	if err != nil {
		return err
	}

	// get temp file
	tmpPath := path + ".temp"
	dstf, err := os.Create(tmpPath)
	if err != nil {
		return err
	}
	defer dstf.Close()

	// write header
	var writed int64 = 0
	tb := a.prehead()
	writed += int64(len(tb))
	if _, err := dstf.Write(tb); err != nil {
		os.Remove(tmpPath)
		return err
	}
	writed += int64(len(header)) + 6
	if len(header) >= 65535 {
		writed += 2
	}
	if err := ops.Write(dstf, header); err != nil {
		os.Remove(tmpPath)
		return err
	}

	// re-encrypt
	oldSm := new(Bencrypt.SymMaster)
	newSm := new(Bencrypt.SymMaster)
	if err := oldSm.Init(METHOD_SYM, oldBodyKey); err != nil {
		return err
	}
	if err := newSm.Init(METHOD_SYM, ops.BodyKey); err != nil {
		return err
	}
	pr, pw := io.Pipe()
	go func() {
		err := oldSm.DeFile(srcf, bodySize, pw)
		if err == nil {
			pw.Close()
		} else {
			pw.CloseWithError(err)
		}
	}()
	if err := newSm.EnFile(pr, plainSize, dstf); err != nil {
		os.Remove(tmpPath)
		return err
	}
	writed += bodySize

	// pad and rename
	if a.DoPad {
		if err := Opsec.PadFile(dstf, Opsec.PadLen(writed)); err != nil {
			return err
		}
	}
	srcf.Close()
	dstf.Close()
	return os.Rename(tmpPath, path)
}
