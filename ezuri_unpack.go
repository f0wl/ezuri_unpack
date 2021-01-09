package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

// check errors as they occur and panic :o
func check(e error) {
	if e != nil {
		panic(e)
	}
}

func scanFile(data []byte, search []byte) (int, error) {
	return bytes.Index(data, search), nil
}

func aesCFBDecrypt(data, key, iv []byte) []byte {
	aesBlockDecrypter, err := aes.NewCipher([]byte(key))
	check(err)
	aesDecrypter := cipher.NewCFBDecrypter(aesBlockDecrypter, iv)
	aesDecrypter.XORKeyStream(data, data)
	return data
}

func newSHA256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func main() {

	fmt.Println("                    _                                 _")
	fmt.Println("    ___ ____  _ _ _(_)        _  _ _ _  _ __  __ _ __| |__")
	fmt.Println("   / -_)_ / || | '_| |       | || | ' \\| '_ \\/ _` / _| / /")
	fmt.Println("   \\___/__|\\_,_|_| |_|  ___   \\_,_|_||_| .__/\\__,_\\__|_\\_\\")
	fmt.Println("                       |___|           |_|                ")
	fmt.Println("\n                  Ezuri Crypter Unpacker")
	fmt.Println("    Marius 'f0wL' Genheimer | https://dissectingmalwa.re")

	if len(os.Args) < 2 {
		fmt.Println("   Usage: go run ezuri_unpack.go packed.bin")
		os.Exit(1)
	}

	// open and read the packed file
	f, openErr := os.Open(os.Args[1])
	check(openErr)
	defer f.Close()

	readseeker := io.ReadSeeker(f)
	packedData, readErr := ioutil.ReadAll(readseeker)
	check(readErr)

	fmt.Printf("\n→ Packed file SHA-256: %v\n", hex.EncodeToString(newSHA256(packedData)))

	// search for the indicator pattern first to check if the sample is likely packed with Ezuri
	indicatorPattern := "6D61696E2E72756E46726F6D4D656D6F7279"
	indicatorBytes, byteErr := hex.DecodeString(indicatorPattern)
	check(byteErr)
	indicatorOffset, scanErr := scanFile(packedData, indicatorBytes)
	check(scanErr)

	if indicatorOffset == -1 {
		fmt.Printf("\n✗ Looks like this sample might not be crypted with Ezuri. Please verify manualy (e.g. Yara rule).\n\n")
		os.Exit(1)
	}

	// search for the pattern: .main.main.init
	offsetPattern := "2E6D61696E006D61696E2E696E6974"
	patternBytes, bytesErr := hex.DecodeString(offsetPattern)
	check(bytesErr)
	offset, scanErr := scanFile(packedData, patternBytes)
	check(scanErr)
	fmt.Printf("✓ Found pattern to calculate offset from\n")

	// slice out AES key and IV
	extractedKey := packedData[offset+16 : offset+48]
	extractedIV := packedData[offset+48 : offset+64]
	fmt.Printf("→ Extracted Key: %v\n", string(extractedKey))
	fmt.Printf("→ Extracted IV: %v\n\n", string(extractedIV))

	// encrypted payload
	encData := packedData[offset+64:]
	// decrypt the payload with AES CFB
	decData := aesCFBDecrypt(encData, extractedKey, extractedIV)
	writeErr := ioutil.WriteFile("decrypted.bin", decData, 0644)
	check(writeErr)
	fmt.Printf("✓ Wrote decrypted payload to decrypted.bin\n")
	fmt.Printf("→ Decrypted file magic: %v\n", string(decData[:4]))
	fmt.Printf("→ Decrypted file SHA-256: %v\n", hex.EncodeToString(newSHA256(encData)))

}
