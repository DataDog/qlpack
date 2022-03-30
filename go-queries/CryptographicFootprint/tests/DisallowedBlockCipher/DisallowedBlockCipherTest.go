package main

import (
	"crypto/aes"
	"crypto/cipher"
)

type ECBTHingAMaBobber struct {}
func (ecb ECBTHingAMaBobber) NewECBDecrypter(b cipher.Block) {}
func (ecb ECBTHingAMaBobber) NewECBEncrypter(b cipher.Block) {}
func (ecb ECBTHingAMaBobber) ECBDecrypter(b cipher.Block) {}
func (ecb ECBTHingAMaBobber) ECB(b cipher.Block) {}

func main() {
	// Setup and examples from go cipher docs
	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	block, _ := aes.NewCipher(key)
	iv := []byte("blah")
	ecb := ECBTHingAMaBobber{}

	// DETECTED - CBC
	cbcEncrypt := cipher.NewCBCDecrypter(block, iv)
	cbcDecrypt := cipher.NewCBCEncrypter(block, iv)

	// DETECTED - ECB
	ecbEncrypt := ecb.NewECBEncrypter(block)
	ecbDecrypt := ecb.NewECBDecrypter(block)
	ecbTruncate := ecb.ECBDecrypter(block)
	ecbMoreTruncation := ecb.ECB(block)

	//DETECTED - CFB
	cfbEncrypt := cipher.NewCFBDecrypter(block, iv)
	cfbDecrypt := cipher.NewCFBEncrypter(block, iv)

	// NOT DETECTED
	gcm, _ := cipher.NewGCM(block)
	gcmNonce, _ := cipher.NewGCMWithNonceSize(block, 16)
	gcmTag, _ := cipher.NewGCMWithTagSize(block, 16)
}

