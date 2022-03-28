import python

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

private import AlgorithmNames

// Adapted from CWE-327 CryptoLibraries

private newtype TCrpytographicAlgorithm =
GoodHashingAlgorithm(string name) {
    isApprovedHashingAlgorithm(name)
} or
GoodEncryptionAlgorithm(string name) {
    isApprovedEncryptionAlgorithm(name)
} or
GoodPasswordHashingAlgorithm(string name) {
    isApprovedPasswordHashingAlgorithm(name)
} or
BadHashingAlgorithm(string name) {
    isDisallowedHashingAlgorithm(name)
} or
BadEncryptionAlgorithm(string name) {
    isDisallowedEncryptionAlgorithm(name)
} or
BadPasswordHashingAlgorithm(string name) {
    isDisallowedPasswordHashingAlgorithm(name)
}

abstract class CryptographicAlgorithm extends TCrpytographicAlgorithm {
  string toString() { result = this.getName() }

  abstract string getName();

  bindingset[name]
  predicate matchesName(string name) {
      exists(name.regexpFind(".*" + this.getName() + ".*", _, _))
  }
}

class ApprovedHashAlgorithm extends GoodHashingAlgorithm, CryptographicAlgorithm {
    string name;
    ApprovedHashAlgorithm() { this = GoodHashingAlgorithm(name) }
    override string getName() { result = name }
}

class ApprovedEncryptionAlgorithm extends GoodEncryptionAlgorithm, CryptographicAlgorithm {
    string name;
    ApprovedEncryptionAlgorithm() { this = GoodEncryptionAlgorithm(name) }
    override string getName() { result = name }
}

class ApprovedPasswordHashAlgorithm extends GoodPasswordHashingAlgorithm, CryptographicAlgorithm {
    string name;
    ApprovedPasswordHashAlgorithm() { this = GoodPasswordHashingAlgorithm(name) }
    override string getName() { result = name }
}

class DisallowedHashAlgorithm extends BadHashingAlgorithm, CryptographicAlgorithm {
    string name;
    DisallowedHashAlgorithm() { this = BadHashingAlgorithm(name) }
    override string getName() { result = name }
}

class DisallowedEncryptionAlgorithm extends BadEncryptionAlgorithm, CryptographicAlgorithm {
    string name;
    DisallowedEncryptionAlgorithm() { this = BadEncryptionAlgorithm(name) }
    override string getName() { result = name }
}

class DisallowedPasswordHashAlgorithm extends BadPasswordHashingAlgorithm, CryptographicAlgorithm {
    string name;
    DisallowedPasswordHashAlgorithm() { this = BadPasswordHashingAlgorithm(name) }
    override string getName() { result = name }
}
