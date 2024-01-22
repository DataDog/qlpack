package main

type TestObject struct {}

func (test TestObject) Bcrypt(s []byte) {}

func (test TestObject) SomeOtherMethod() {}

func main() {
	foo := []byte("bar")
	test := TestObject{}

	test.Bcrypt(foo)

	// DETECTED - Approved Password Callee
	test.Bcrypt(foo)

	// NON CRYPTO - NOT DETECTED - This tests that our indicator for false positives works
	test.Bcrypt(foo)

	// NOT DETECTED - Not an approved item, shouldn't be caught
	test.SomeOtherMethod()
}

