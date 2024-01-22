package main

import (
	"github.com/gosnmp/gosnmp"
)

func main() {
	var baz gosnmp.SnmpV3AuthProtocol
	baz = gosnmp.SHA256

	// DETECTED - Approved Hash Expression
	baz = gosnmp.SHA256

	// NON CRYPTO - NOT DETECTED - This tests that our indicator for false positives works
	baz = gosnmp.SHA256

	// NOT DETECTED - Not an approved item, shouldn't be caught
	baz = gosnmp.MD5
}

