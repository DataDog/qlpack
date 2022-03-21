package main

import (
	"crypto/des"
	"crypto/rand"
)

func main() {
	des.NewCipher(foo)

	// DETECTED - Disallowed Encryption Package
	des.NewCipher(foo)

	// NON CRYPTO - NOT DETECTED - This tests that our indicator for false positives works
	des.NewCipher(foo)

	// NOT DETECTED - Not an approved item, shouldn't be caught
	rand.Read([]byte("foo"))
}

