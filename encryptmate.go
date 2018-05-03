package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"io"
	"log"
	"os"
)

func encrypt(key []byte, message string) (encmess string, err error) {
	plainText := []byte(message)
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	//IV needs to be unique, but doesn't have to be secure.
	//It's common to put it at the beginning of the ciphertext.
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	//returns to base64 encoded string
	encmess = base64.URLEncoding.EncodeToString(cipherText)
	return
}

func decrypt(key []byte, securemess string) (decodedmess string, err error) {
	cipherText, err := base64.URLEncoding.DecodeString(securemess)
	if err != nil {
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	if len(cipherText) < aes.BlockSize {
		err = errors.New("Ciphertext block size is too short!")
		return
	}

	//IV needs to be unique, but doesn't have to be secure.
	//It's common to put it at the beginning of the ciphertext.
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(cipherText, cipherText)

	decodedmess = string(cipherText)
	return
}

func main() {
	keyPtr := flag.String("key", "", "Encryption/Decryption Key ")
	stringPtr := flag.String("value", "", "string to encrypt or decrypt ")
	encryptPtr := flag.Bool("encrypt", false, "encrypt action")
	decryptPtr := flag.Bool("decrypt", false, "decrypt action")

	flag.Parse()
	cipherKey := []byte("")

	if *keyPtr != "" {
		cipherKey = []byte(*keyPtr)
	} else if os.Getenv("GO_ENCRYPTION_KEY") != "" {
		cipherKey = []byte(os.Getenv("GO_ENCRYPTION_KEY"))
	} else {
		panic("no key define to encrypt")
	}

	msg := *stringPtr
	enc := *stringPtr

	if *encryptPtr {
		if encrypted, err := encrypt(cipherKey, msg); err != nil {
			log.Println(err)
		} else {
			log.Printf("ENCRYPTED: %s\n", encrypted)
		}
	}

	if *decryptPtr {
		if decrypted, err := decrypt(cipherKey, enc); err != nil {
			log.Println(err)
		} else {
			log.Printf("DECRYPTED: %s\n", decrypted)
		}
	}
}
