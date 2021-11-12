package einsteinkeys

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
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

var clear map[string]func()

func init() {
	clear = make(map[string]func())
	clear["linux"] = func() {
		cmd := exec.Command("clear")
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
	clear["windows"] = func() {
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
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

	color.Cyan("Validating key: " + keyString)

	resp, err := http.Get("https://keys.joeyli.dev/keys?key=" + keyString)
	if err != nil {
		log.Fatal(err)
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
		log.Fatal(err)
		return
	}

	if !key.Enabled {
		color.Red("This key is disabled")
		return
	}

	color.Cyan("This key is enabled")
	color.Cyan("This software is licensed to: " + key.Licensee)
	fmt.Println("")
	checksum := checkSUM()
	color.Cyan("The Sha256Checksum of this binary is:           " + checksum)
	color.Cyan("The Sha256Checksum associated with this key is: " + key.Sha256Checksum)
	if key.Sha256Checksum != checksum {
		color.Red("This binary's integrity is compromised. Contact Einstein if you believe this isn't true")
		return fmt.Errorf("Errored")
	}

	color.GreenString("This binary has been verified and it's integrity is intact")
	color.Cyan("Continueing program in 3 seconds...")
	time.Sleep(time.Second * 3)

	CallClear()
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

func CallClear() {
	value, ok := clear[runtime.GOOS] //runtime.GOOS -> linux, windows, darwin etc.
	if ok {                          //if we defined a clear func for that platform:
		value() //we execute it
	} else { //unsupported platform
		panic("Your platform is unsupported! I can't clear terminal screen :(")
	}
}
