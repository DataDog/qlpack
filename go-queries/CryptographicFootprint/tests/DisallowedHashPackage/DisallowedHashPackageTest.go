package main

import (
	"crypto/sha256"
	"crypto/md5"
)

func main() {
	foo := []byte("bar")

	md5.Sum(foo)

	// DETECTED - Disallowed Hash Package
	md5.Sum(foo)

	// NON CRYPTO - NOT DETECTED - This tests that our indicator for false positives works
	md5.Sum(foo)

	// NOT DETECTED - Approved item, shouldn't be caught
	sha256.Sum256(foo)
}

