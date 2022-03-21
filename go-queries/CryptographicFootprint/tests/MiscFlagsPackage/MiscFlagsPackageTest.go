package main

import (
	"crypto/tls"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	foo := []byte("bar")

	tls.X509KeyPair(foo, foo)

	// DETECTED - Misc Flags Package
	tls.X509KeyPair(foo, foo)

	// NON CRYPTO - NOT DETECTED - This tests that our indicator for false positives works
	tls.X509KeyPair(foo, foo)

	// NOT DETECTED - Not an misc item, shouldn't be caught
	bcrypt.GenerateFromPassword(foo, 11)
}

