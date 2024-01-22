package main

type TestObject struct {}

func (test TestObject) Sha256(s []byte) {}

func (test TestObject) SomeOtherMethod() {}

func main() {
	foo := []byte("bar")
	test := TestObject{}

	test.Sha256(foo)

	// DETECTED - Approved Hash Callee
	test.Sha256(foo)

	// NON CRYPTO - NOT DETECTED - This tests that our indicator for false positives works
	test.Sha256(foo)

	// NOT DETECTED - Not an approved item, shouldn't be caught
	test.SomeOtherMethod()
}

