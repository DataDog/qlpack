package main

import (
	"github.com/gosnmp/gosnmp"
)

func main() {
	var baz gosnmp.SnmpV3AuthProtocol
	baz = gosnmp.MD5

	// DETECTED - Disallowed Hash Expression
	baz = gosnmp.MD5

	// NON CRYPTO - NOT DETECTED - This tests that our indicator for false positives works
	baz = gosnmp.MD5

	// NOT DETECTED - Approved hash expression, shouldn't be caught
	baz = gosnmp.SHA512
}

