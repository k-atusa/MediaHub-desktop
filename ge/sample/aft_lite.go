// test798b : project USAG AFT-desktop lite
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/k-atusa/USAG-Lib/Bencode"
	"github.com/k-atusa/USAG-Lib/Bencrypt"
	"github.com/k-atusa/USAG-Lib/Opsec"
)

// command line parser
type Config struct {
	Mode     string
	Target   string
	Output   string
	AlgoType string
	ImgType  string

	PW    []byte // masked
	KF    []byte // masked
	Msg   string
	DoPad bool
	mask  *Bencrypt.Masker
}

func (cfg *Config) Init() {
	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError) // empty string means auto
	fs.StringVar(&cfg.Mode, "m", "help", "work mode: import, export, view, trim")
	fs.StringVar(&cfg.Output, "o", "", "output folder")
	fs.StringVar(&cfg.AlgoType, "algo", "arg2st", "algorithm type: arg2low, arg2st")
	fs.StringVar(&cfg.ImgType, "img", "webp", "image type: webp, png, bin")
	fs.StringVar(&cfg.Msg, "msg", "", "message")
	fs.BoolVar(&cfg.DoPad, "nopad", false, "disable padding")

	// get password and keyfile
	tempPW, kfpath := "", ""
	fs.StringVar(&tempPW, "pw", "", "password")
	fs.StringVar(&kfpath, "kf", "", "key file path")

	// parse and get target folder, mask
	fs.Parse(os.Args[1:])
	cfg.Target = fs.Arg(0)

	// mask password
	cfg.mask = Bencrypt.GetMasker(-1)
	pwb := Bencode.NormPW(tempPW)
	defer sclear(pwb)
	cfg.PW, _ = cfg.mask.XOR(pwb)
	tempPW = ""

	// mask keyfile
	var key []byte
	defer func() { sclear(key) }()
	if kfpath == "" {
		key = nil
	} else if _, err := os.Stat(kfpath); err == nil { // file
		fmt.Println("reading keyfile")
		key, err = os.ReadFile(kfpath)
		if err != nil {
			fmt.Println(err)
			key = nil
		}
	}
	if len(key) > 4096 {
		key = key[:4096]
	}
	crcv_kf := Opsec.Crc32(key)
	cfg.KF, _ = cfg.mask.XOR(key)

	// flip flag, end configuration
	cfg.DoPad = !cfg.DoPad
	fmt.Printf("PW: %dB, KF: %dB (%s)\n", len(cfg.PW), len(cfg.KF), crcv_kf)
	fmt.Println("configuration completed")
}

// main functions
func f_import() error {
	// check arguments
	if Cfg.Target == "" || Cfg.Output == "" {
		return errors.New("target and output are required for import")
	}
	if err := os.MkdirAll(Cfg.Output, 0755); err != nil {
		return err
	}
	info, err := os.Stat(Cfg.Output)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("output is not a directory")
	}

	// make AVault
	v := &AVault{
		Path:     Cfg.Output,
		DoPad:    Cfg.DoPad,
		Mask:     Bencrypt.GetMasker(-1),
		AlgoType: Cfg.AlgoType,
		Ext:      Cfg.ImgType,
		VaultKey: Bencrypt.Random(64), // randgen acts like masked
		TreeView: make(map[string][]string),
		PtoCtbl:  make(map[string]string),
		CtoPtbl:  make(map[string]string),
	}
	defer sclear(v.VaultKey)
	pw, _ := Cfg.mask.XOR(Cfg.PW)
	defer sclear(pw)
	kf, _ := Cfg.mask.XOR(Cfg.KF)
	defer sclear(kf)
	if err := v.StoreAccount(pw, kf, Cfg.Msg); err != nil {
		return err
	}

	// search target folder
	entries, err := os.ReadDir(Cfg.Target)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		fullPath := filepath.Join(Cfg.Target, entry.Name())
		fmt.Printf("Adding: %s\n", fullPath)
		err = v.Add(fullPath, "")
		if err != nil {
			return err
		}
	}

	fmt.Printf("\nSuccessfully imported vault at: %s\n", v.Path)
	return nil
}

func f_export() error {
	// check arguments
	if Cfg.Target == "" || Cfg.Output == "" {
		return errors.New("target and output are required for export")
	}
	if err := os.MkdirAll(Cfg.Output, 0755); err != nil {
		return err
	}

	// load vault
	v := &AVault{
		Path: Cfg.Target,
		Mask: Bencrypt.GetMasker(-1),
	}
	defer func() { sclear(v.VaultKey) }()
	pw, _ := Cfg.mask.XOR(Cfg.PW)
	defer sclear(pw)
	kf, _ := Cfg.mask.XOR(Cfg.KF)
	defer sclear(kf)
	msg, err := v.Load(pw, kf)
	if msg != "" {
		fmt.Printf("[msg] %s\n", msg)
	}
	if err != nil {
		return err
	}
	fmt.Println("Vault unlocked")

	// restore files
	for plainName := range v.PtoCtbl {
		// folder: make directory
		if strings.HasSuffix(plainName, "/") {
			dirPath := filepath.Join(Cfg.Output, plainName)
			if err := os.MkdirAll(dirPath, 0755); err != nil {
				return err
			}
			fmt.Printf("Created directory: %s\n", plainName)
			continue
		}

		// find cipher path
		cipher, ok := v.PtoCtbl[plainName]
		if !ok {
			return errors.New("file not found in vault")
		}
		cipherPath := filepath.Join(v.Path, cipher)

		// make output path
		targetPath := filepath.Join(Cfg.Output, plainName)
		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			return err
		}

		// decrypt file
		if err := v.Bypass(cipherPath, targetPath, false); err != nil {
			return err
		}
		fmt.Printf("Exported file: %s\n", plainName)
	}

	fmt.Printf("\nSuccessfully exported to: %s\n", Cfg.Output)
	return nil
}

func f_view() error {
	// check arguments, load vault
	if Cfg.Target == "" {
		return errors.New("target is required for view")
	}
	v := &AVault{
		Path: Cfg.Target,
		Mask: Bencrypt.GetMasker(-1),
	}
	defer func() { sclear(v.VaultKey) }()
	pw, _ := Cfg.mask.XOR(Cfg.PW)
	defer sclear(pw)
	kf, _ := Cfg.mask.XOR(Cfg.KF)
	defer sclear(kf)
	msg, err := v.Load(pw, kf)
	if err != nil {
		fmt.Printf("[msg] %s\n", msg)
		return err
	}

	// print vault metadata
	key, _ := Cfg.mask.XOR(v.VaultKey)
	defer sclear(key)
	fmt.Println("========== AFT Vault Metadata ==========")
	fmt.Printf("Message     : %s\n", msg)
	fmt.Printf("Algorithm   : %s\n", v.AlgoType)
	fmt.Printf("File Format : %s\n", v.Ext)
	fmt.Printf("Master Key  : %s\n", Bencode.Encode64h(key))
	fmt.Printf("Total Items : %d\n", len(v.PtoCtbl))

	// print file list
	fmt.Println("\n========== Files List ==========")
	if len(v.TreeView[""]) == 0 {
		fmt.Println("(No items found in vault)")
	}
	for _, name := range v.TreeView[""] {
		if strings.HasSuffix(name, "/") {
			fmt.Println(name)
			children := v.TreeView[name]
			for _, child := range children {
				fmt.Printf("    %s\n", child)
			}
		} else {
			fmt.Println(name)
		}
	}
	return nil
}

func f_trim() error {
	if Cfg.Target == "" {
		return errors.New("target is required for trim")
	}
	v := &AVault{
		Path:  Cfg.Target,
		Mask:  Bencrypt.GetMasker(-1),
		DoPad: Cfg.DoPad,
	}
	defer func() { sclear(v.VaultKey) }()
	pw, _ := Cfg.mask.XOR(Cfg.PW)
	defer sclear(pw)
	kf, _ := Cfg.mask.XOR(Cfg.KF)
	defer sclear(kf)
	msg, err := v.Load(pw, kf)
	if err != nil {
		return err
	}

	// trim vault
	fmt.Println("Triming vault...")
	count, err := v.Trim()
	fmt.Printf("Sync completed: %d items cleaned.\n", count)
	if err != nil {
		return err
	}

	// make new key
	oldKey := v.VaultKey
	defer sclear(oldKey)
	newKey := Bencrypt.Random(64) // randgen is already masked
	defer sclear(newKey)
	fmt.Println("New vault key created...")

	// re-encrypt all files
	errFlag := false
	defer os.RemoveAll("./aft_plain.temp")
	for plain, cipher := range v.PtoCtbl {
		if strings.HasSuffix(plain, "/") {
			continue
		}
		fmt.Printf("Re-encrypting: %s\n", plain)
		err = v.ReCrypt(cipher, oldKey, newKey)
		if err != nil {
			fmt.Printf("    Skip: Re-encryption failed (%v)\n", err)
			errFlag = true
			continue
		}
	}

	// remove old files
	if errFlag {
		return errors.New("Error occurred during re-encryption")
	}
	filepath.Walk(v.Path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.HasSuffix(path, ".temp") {
			os.Remove(path)
		}
		return nil
	})

	// save account and name
	fmt.Println("Saving account and name...")
	v.VaultKey = newKey
	err = v.StoreAccount(pw, kf, msg)
	if err != nil {
		return err
	}
	return v.StoreName()
}

var Cfg Config

func main() {
	defer func() {
		if err := recover(); err != nil {
			fmt.Printf("[PANIC] %v", err)
		}
	}()
	var err error
	Cfg.Init()
	switch Cfg.Mode {
	case "import":
		err = f_import()
	case "export":
		err = f_export()
	case "view":
		err = f_view()
	case "trim":
		err = f_trim()
	default: // help
		fmt.Print(AFT_VERSION + "\n\n")
		fmt.Println("-m mode [import|export|view|trim] -o outdir -pw password -kf keyfile -msg message")
		fmt.Println("-algo [arg2low|arg2st] -img [webp|png|bin]")
		fmt.Println("import: target -> outdir +(pw, kf, msg, nopad)")
		fmt.Println("export: target -> outdir +(pw, kf)")
		fmt.Println("view: list all files +(pw, kf)")
		fmt.Println("trim: trim and rebuild +(pw, kf, nopad)")
	}
	if err != nil {
		fmt.Printf("\n[ERROR] %v\n", err)
	}
}
