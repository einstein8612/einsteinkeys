package einsteinkeys

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/fatih/color"
)

type Key struct {
	Key                string    `json:"key"`
	Licensee           string    `json:"licensee"`
	ProductDescription string    `json:"product_description"`
	Created            time.Time `json:"created"`
	Sha256Checksum     string    `json:"sha256_checksum"`
	Enabled            bool      `json:"enabled"`
}

func Validate(keyString string) (err error) {
	color.Cyan(`  ______ _           _       _         _  __`)
	color.Cyan(` |  ____(_)         | |     (_)       | |/ /`)
	color.Cyan(` | |__   _ _ __  ___| |_ ___ _ _ __   | ' / ___ _   _ ___`)
	color.Cyan(` |  __| | | '_ \/ __| __/ _ \ | '_ \  |  < / _ \ | | / __|`)
	color.Cyan(` | |____| | | | \__ \ ||  __/ | | | | | . \  __/ |_| \__ \`)
	color.Cyan(` |______|_|_| |_|___/\__\___|_|_| |_| |_|\_\___|\__, |___/`)
	color.Cyan(`                                                 __/ |`)
	color.Cyan(`                                                |___/`)

	log.Println(color.CyanString("Validating key: " + keyString))

	resp, err := http.Get("https://keys.joeyli.dev/keys?key=" + keyString)
	if err != nil {
		return
	}

	if resp.StatusCode != http.StatusOK {
		color.Red("This key is invalid")
		return
	}

	var key Key
	respBytes, err := io.ReadAll(resp.Body)
	err = json.Unmarshal(respBytes, &key)
	if err != nil {
		return
	}

	if !key.Enabled {
		color.Red("This key is disabled")
		return
	}

	log.Println(color.CyanString("This key is enabled"))
	log.Println(color.CyanString("This software is licensed to: " + key.Licensee))
	fmt.Println("")
	checksum := checkSUM()
	log.Println(color.CyanString("The Sha256Checksum of this binary is:           " + checksum))
	log.Println(color.CyanString("The Sha256Checksum associated with this key is: " + key.Sha256Checksum))
	if key.Sha256Checksum == checksum {
		log.Println(color.GreenString("This binary has been verified and it's integrity is intact"))
	} else {
		log.Println(color.RedString("This binary's integrity is compromised. Contact Einstein if you believe this isn't true"))
	}
	return
}

func checkSUM() string {
	hasher := sha256.New()
	f, err := os.Open(os.Args[0])
	if err != nil {
		os.Exit(0)
	}

	defer f.Close()
	if _, err = io.Copy(hasher, f); err != nil {
		os.Exit(0)
	}

	return fmt.Sprintf("%x", hasher.Sum(nil))
}
