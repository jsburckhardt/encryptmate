package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
)

func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func encrypt(data []byte, passphrase string) []byte {
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Println("first")
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println("second")
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

func decrypt(data []byte, passphrase string) []byte {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("third")
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Println("fourth")
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Println("fifth")
		panic(err.Error())
	}
	return plaintext
}

func main() {

	keyPtr := flag.String("key", "", "Encryption/Decryption Key ")
	stringPtr := flag.String("value", "", "string to encrypt or decrypt ")
	encryptPtr := flag.Bool("encrypt", false, "encrypt action")
	decryptPtr := flag.Bool("decrypt", false, "decrypt action")

	flag.Parse()

	//fmt.Println("key:", *keyPtr)
	//fmt.Println("string:", *stringPtr)
	//fmt.Println("encrypt?", *encryptPtr)
	//fmt.Println("decrypt?", *decryptPtr)
	//fmt.Println("tail:", flag.Args())

	if *encryptPtr {
		ciphertext := encrypt([]byte(*stringPtr), *keyPtr)
		fmt.Printf("Encrypted: %x\n", ciphertext)
	}
	if *decryptPtr {
		plaintext := decrypt([]byte(*stringPtr), *keyPtr)
		fmt.Printf("Decrypted: %s\n", plaintext)
	}
	//encryptFile("sample.txt", []byte("Hello World"), "password1")
	//fmt.Println(string(decryptFile("sample.txt", "password1")))
}
