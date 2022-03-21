package main

type TestObject struct {}

func (test TestObject) Des(s []byte) {}

func (test TestObject) SomeOtherMethod() {}

func main() {
	foo := []byte("bar")
	test := TestObject{}

	test.Des(foo)

	// DETECTED - Disallowed Encryption Callee
	test.Des(foo)

	// NON CRYPTO - NOT DETECTED - This tests that our indicator for false positives works
	test.Des(foo)

	// NOT DETECTED - Not an approved item, shouldn't be caught
	test.SomeOtherMethod()
}

