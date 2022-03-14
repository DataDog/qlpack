// Adapted from codeql-go's experimental CWE-327 Weak Key Algorithm examples

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
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/hkdf"
	openssl "github.com/Luzifer/go-openssl/v4"
	"github.com/spacemonkeygo/openssl"
	"github.com/gosnmp/gosnmp"
)

func main() {
	foo := "bar"
	var baz gosnmp.SnmpV3AuthProtocol

    // DETECTED - Approved Encryption Callee
	test.Aes128(foo)

	// DETECTED - Approved Encryption Package
	rsa.GenerateKey(foo, 128)

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

