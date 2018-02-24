package main

import (
	"crypto/sha1"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
)

var (
	print = fmt.Println
)

func main() {

	password := getPassword()

	hash, hashPrefix := getHash(password)
	print("[Password Hash] " + hash)

	pwnedHashes := getPwnedHashes(hashPrefix)

	pwnedCount := analyzeHashes(hash, pwnedHashes)

	if pwnedCount > 0 {
		fmt.Printf("Your password has been pwned %v times. You better change that.", pwnedCount)
	} else {
		print("Your password has yet to be pwned (that we know of)")
	}

}

func analyzeHashes(hash string, pwnedHashes []PwnedHash) int {
	for _, x := range pwnedHashes {
		if x.Hash == hash[5:] {
			return x.TimesPwned
		}
	}
	return 0
}

func getPwnedHashes(hashPrefix string) []PwnedHash {

	var retval []PwnedHash

	targetUrl := "https://api.pwnedpasswords.com/range/{{hashPrefix}}"
	targetUrl = strings.Replace(targetUrl, "{{hashPrefix}}", hashPrefix, 1)

	print("[Checking API] " + targetUrl)

	resp, err := http.Get(targetUrl)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	hashes := strings.Split(string(respBytes), "\r\n")

	for _, x := range hashes {

		hashSplit := strings.Split(x, ":")

		timesPwned, err := strconv.Atoi(hashSplit[1])
		if err != nil {
			log.Fatal(err)
		}
		pwnedHash := PwnedHash{
			Hash:       hashSplit[0],
			TimesPwned: timesPwned,
		}
		retval = append(retval, pwnedHash)
	}

	return retval
}

func getHash(password string) (string, string) {
	h := sha1.New()
	io.WriteString(h, password)
	hash := strings.ToUpper(fmt.Sprintf("%x", h.Sum(nil)))
	hashPrefix := hash[:5]

	return hash, hashPrefix
}

func getPassword() string {
	fmt.Print("Enter password: ")
	var input string
	fmt.Scanln(&input)

	if input == "" {
		log.Fatal("[ERROR] Invalid input entered")
	}

	return input
}

type PwnedHash struct {
	Hash       string
	TimesPwned int
}
