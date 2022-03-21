package main

import (
	"crypto/sha256"
	"crypto/sha1"
)

func main() {
	foo := []byte("bar")

	sha256.Sum256(foo)

	// DETECTED - Approved Hash Package
	sha256.Sum256(foo)

	// NON CRYPTO - NOT DETECTED - This tests that our indicator for false positives works
	sha256.Sum256(foo)

	// NOT DETECTED - Not an approved item, shouldn't be caught
	sha1.Sum(foo)
}

