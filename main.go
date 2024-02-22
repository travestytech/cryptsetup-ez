package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/martinjungblut/go-cryptsetup"
	"golang.org/x/term"
)

const (
	EINIT = 11
	EFORM = 12
	EPASS = 13
	EDEAC = 14
	EACTP = 15
	ELOAD = 16
)

func main() {
	closeF := flag.String("close", "", "Close an opened LUKS-encrypted drive")
	encryptF := flag.String("encrypt", "", "Encrypt a drive with LUKS2")
	nameF := flag.String("name", "", "Mapped name of device; to be used with open")
	openF := flag.String("open", "", "Open a LUKS-encrypted drive; requires name flag")
	verboseF := flag.Bool("v", false, "Verbose mode")

	flag.Parse()

	cryptsetup.SetLogCallback(func(level int, message string) {
		if *verboseF {
			fmt.Printf(message)
		}
	})

	switch {
	case *closeF != "":
		close(*closeF)
		return
	case *encryptF != "":
		encrypt(*encryptF)
		return
	case *openF != "" && *nameF != "":
		open(*openF, *nameF)
		return
	default:
		flag.PrintDefaults()
	}
}

func close(name string) {
	device, err := cryptsetup.InitByName(name)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error initializing device by name", name)
		os.Exit(EINIT)
	}
	defer device.Free()

	err = device.Deactivate(name)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error deactivating device", name)
		os.Exit(EDEAC)
	}
}

func encrypt(dev string) {
	pbkdftype := cryptsetup.PbkdfType{
		Type:            "argon2id",
		Hash:            "sha512",
		TimeMs:          2 * 1000,
		Iterations:      2,
		MaxMemoryKb:     16 * 1024,
		ParallelThreads: 2,
		Flags:           1,
	}
	luks2 := cryptsetup.LUKS2{
		SectorSize: 512,
		PBKDFType:  &pbkdftype,
	}

	device, err := cryptsetup.Init(dev)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error initializing device", dev)
		os.Exit(EINIT)
	}
	defer device.Free()

	fmt.Println("Enter password:")
	passB, err := term.ReadPassword(int(os.Stdin.Fd()))

	err = device.Format(luks2, cryptsetup.GenericParams{Cipher: "aes", CipherMode: "xts-plain64", VolumeKeySize: 512 / 8})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error formatting device")
		os.Exit(EFORM)
	}

	err = device.KeyslotAddByVolumeKey(0, "", string(passB))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error setting password")
		os.Exit(EPASS)
	}

	fmt.Println("Formatted device:", device.Type())
}

func open(dev string, name string) {
	device, err := cryptsetup.Init(dev)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error initializing device", dev)
		os.Exit(EINIT)
	}
	defer device.Free()

	err = device.Load(nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error loading device", dev)
		os.Exit(ELOAD)
	}

	fmt.Println("Enter password:")
	passB, err := term.ReadPassword(int(os.Stdin.Fd()))

	err = device.ActivateByPassphrase(name, 0, string(passB), 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error activating device by passphrase", dev)
		os.Exit(EACTP)
	}
}
