package main

type TestObject struct {}

func (test TestObject) Hkdf(s []byte) {}

func (test TestObject) SomeOtherMethod() {}

func main() {
	foo := []byte("bar")
	test := TestObject{}

	test.Hkdf(foo)

	// DETECTED - Disallowed Password Callee
	test.Hkdf(foo)

	// NON CRYPTO - NOT DETECTED - This tests that our indicator for false positives works
	test.Hkdf(foo)

	// NOT DETECTED - Not an approved item, shouldn't be caught
	test.SomeOtherMethod()
}

