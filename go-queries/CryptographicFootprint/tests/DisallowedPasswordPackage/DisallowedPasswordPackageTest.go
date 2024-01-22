package main

import (
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/hkdf"
)

func main() {
	foo := []byte("bar")

	hkdf.New(foo, foo, foo, foo)

	// DETECTED - Disallowed Password Package
	hkdf.New(foo, foo, foo, foo)

	// NON CRYPTO - NOT DETECTED - This tests that our indicator for false positives works
	hkdf.New(foo, foo, foo, foo)

	// NOT DETECTED - Not an approved item, shouldn't be caught
	bcrypt.GenerateFromPassword(foo, 11)
}

