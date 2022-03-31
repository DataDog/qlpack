package main

import (
	"crypto/rsa"
	"crypto/rand"
)

func main() {
	rsa.GenerateKey(rand.Reader, 128)

	// DETECTED - Approved Encryption Package
	rsa.GenerateKey(rand.Reader, 128)

	// NON CRYPTO - NOT DETECTED - This tests that our indicator for false positives works
	rsa.GenerateKey(rand.Reader, 128)

	// NOT DETECTED - Not an approved item, shouldn't be caught
	rand.Read([]byte("foo"))
}

