package main

import (
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/hkdf"
)

func main() {
	foo := []byte("bar")

	bcrypt.GenerateFromPassword(foo, 3)

	// DETECTED - Approved Password Package
	bcrypt.GenerateFromPassword(foo, 7)

	// NON CRYPTO - NOT DETECTED - This tests that our indicator for false positives works
	bcrypt.GenerateFromPassword(foo, 11)

	// NOT DETECTED - Not an approved item, shouldn't be caught
	hkdf.New()
}

