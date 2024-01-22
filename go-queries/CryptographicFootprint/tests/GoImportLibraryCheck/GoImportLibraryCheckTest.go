package main

import (
	// DETECTED
	"crypto/aes"
	"crypto/rsa"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	// NON CRYPTO - testing that false positive marking works
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/rand"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/hkdf"
	openssl "github.com/Luzifer/go-openssl/v4"
	openssl2 "github.com/spacemonkeygo/openssl"
	"go.dedis.ch/kyber/v3"
	"github.com/coinbase/kryptology@1.6.0"

	// NOT DETECTED
	"github.com/gosnmp/gosnmp"
	"math/rand"
)

func main() {

}

