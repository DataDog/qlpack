// Adapted from codeql-go's experimental CWE-327 Weak Key Algorithm examples
// TODO - turn this test into an class that each type subclasses from since there's stuff we want to test everyone like NOT CRPYTO

package main

import (
	"crypto/aes"
	"crypto/rsa"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/rand"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/hkdf"
	openssl "github.com/Luzifer/go-openssl/v4"
	openssl2 "github.com/spacemonkeygo/openssl"
	"github.com/gosnmp/gosnmp"
)

type TestObject struct {
}

func (test TestObject) Aes128(s []byte) {
}

func (test TestObject) Sha256(s []byte) {
}

func (test TestObject) Bcrypt(s []byte) {
}

func (test TestObject) Des(s []byte) {
}

func (test TestObject) Md5(s []byte) {
}

func (test TestObject) Hkdf(s []byte) {
}

func (test TestObject) tls(s []byte) {
}

func (test TestObject) doingsomething(s ...string) {
}

func main() {
	foo := []byte("bar")
	var baz gosnmp.SnmpV3AuthProtocol
	test := TestObject{}

    // DETECTED - Approved Encryption Callee
	test.Aes128(foo)

	// DETECTED - Approved Encryption Package
	rsa.GenerateKey(rand.Reader, 128)

	// NON CRYPTO - This tests that our indicator for false positives works
	rsa.GenerateKey(rand.Reader, 128)

	// DETECTED - Approved Hash Callee
	test.Sha256(foo)

	// DETECTED - Approved Hash Package
	sha256.Sum256(foo)

	// DETECTED - Approved Hash Expression
	baz = gosnmp.SHA256

	// DETECTED - Approved Password Callee
	test.Bcrypt(foo)

	// DETECTED - Approved Password Package
	bcrypt.GenerateFromPassword(foo, 11)

    // DETECTED - Disallowed Encryption Callee
	test.Des(foo)

	// DETECTED - Disallowed Encryption Package
	des.NewCipher(foo)

	// DETECTED - Disallowed Hash Callee
	test.Md5(foo)

	// DETECTED - Disallowed Hash Package
	md5.Sum(foo)

	// DETECTED - Disallowed Hash Expression
	baz = gosnmp.MD5

	// DETECTED - Disallowed Password Callee
    test.Hkdf(foo)

	// DETECTED - Disallowed Password Package
    hkdf.New(foo, foo, foo, foo)

	// DETECTED - Disallowed AES cipher size
	aes.NewCipher([]byte("123456789012345"))

	// DETECTED - Misc Flags Callee
    test.tls(foo)

	// DETECTED - Misc Flags Package
	tls.X509KeyPair(foo, foo)

	// NOT DETECTED - crypto as a parameter
    test.doingsomething("AES", "MD5", "SHA256")

    // NOT DETECTED - Allowed AES cipher size
    aes.NewCipher([]byte("1234567890123456"))

}

