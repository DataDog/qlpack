package main

import (
	"crypto/aes"
)

func main() {
	aes.NewCipher([]byte("123456789012345"))

	// DETECTED - Disallowed AES cipher size
	aes.NewCipher([]byte("123456789012345"))

	// NON CRYPTO - DETECTED - This tests that we don't care about the false positive indicator, this is too specific
	aes.NewCipher([]byte("123456789012345"))

	// NOT DETECTED - Allowed AES cipher size
	aes.NewCipher([]byte("1234567890123456"))
}

