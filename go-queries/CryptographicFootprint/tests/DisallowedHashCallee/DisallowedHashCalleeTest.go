package main

type TestObject struct {}

func (test TestObject) Md5(s []byte) {}

func (test TestObject) SomeOtherMethod() {}

func main() {
	foo := []byte("bar")
	test := TestObject{}

	test.Md5(foo)

	// DETECTED - Disallowed Hash Callee
	test.Md5(foo)

	// NON CRYPTO - NOT DETECTED - This tests that our indicator for false positives works
	test.Md5(foo)

	// NOT DETECTED - Not an approved item, shouldn't be caught
	test.SomeOtherMethod()
}

