package main

import (
	"crypto/aes"
)

type TestObject struct {}

func (test TestObject) Aes128(s []byte) {}

func (test TestObject) SomeOtherMethod() {}

func main() {
	foo := []byte("bar")
	test := TestObject{}

	// DETECTED - Approved Encryption Callee
	test.Aes128(foo)

	// NON CRYPTO - NOT DETECTED - This tests that our indicator for false positives works
	test.Aes128(foo)

	// NOT DETECTED - Not an approved item, shouldn't be caught
	test.SomeOtherMethod()
}

