package main

type TestObject struct {}

func (test TestObject) Tls(s []byte) {}

func (test TestObject) SomeOtherMethod() {}

func main() {
	foo := []byte("bar")
	test := TestObject{}

	test.Tls(foo)

	// DETECTED - Misc Flags Callee
    test.Tls(foo)

	// NON CRYPTO - NOT DETECTED - This tests that our indicator for false positives works
	test.Tls(foo)

	// NOT DETECTED - Not an approved item, shouldn't be caught
	test.SomeOtherMethod()
}

