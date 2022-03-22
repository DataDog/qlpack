module AlgorithmNames {
    predicate isApprovedHashingAlgorithm(string name) {
        name =
            [
                "SHA2", "SHA3", "HMAC", "SHA256", "SHA384", "SHA512", "ES256", "ES384",
                "DSA", "ECDSA", "ECDSA256", "ECDSA384", "ECDSA512", "ES512"
            ]
    }

    predicate isDisallowedHashingAlgorithm(string name) {
        name =
            [
                "BLAKE2B", "BLAKE2S", "CURVE25519", "ED25519", "MD2", "MD4",
                "MD5", "RIPEMD160", "SHA0", "SHA1", "SHA224", "HAVEL128",
                "PANAMA", "RIPEMD", "RIPEMD128", "RIPEMD256", "RIPEMD320"
            ]
    }

    predicate isApprovedEncryptionAlgorithm(string name) {
        name =
            [
                 "AES", "AES128", "AES192", "AES256", "RSA"
            ]
    }

    predicate isDisallowedEncryptionAlgorithm(string name) {
        name =
            [
                "BLOWFISH", "CAST5", "CHACHA20", "CHACHA20POLY1305", "OPENPGP",
                "OTR", "SALSA20", "TEA", "TWOFISH", "XTEA", "XTS", "RC4", "DES",
                "3DES", "RABBIT", "ARC5", "RC5", "TRIPLEDES", "TDEA", "TRIPLEDEA",
                "ARC2", "RC2", "ARC4", "ARCFOUR", "IDEA", "IPES", "GPG"
            ]
    }

    predicate isApprovedPasswordHashingAlgorithm(string name) {
        name =
            [
                "ARGON2", "PBKDF2", "BCRYPT", "SCRPYT"
            ]
    }

    predicate isDisallowedPasswordHashingAlgorithm(string name) {
        name =
            [
                "HKDF"
            ]
    }
}
