/**
 * Adapted from the experimental CWE-327 CryptoLibraries
 * Currently, this only supports Go
 * Python is going to need its own class
 */

import go

module AlgorithmNames {
    string nonCrypto() {
        result = ".*NON CRYPTO.*"
    }

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
                "PBKDF2"
            ]
    }

    predicate isDisallowedPasswordHashingAlgorithm(string name) {
        name =
            [
                "HKDF", "ARGON2", "BCRYPT", "SCRYPT"
            ]
    }

    predicate isDisallowedBlockCipherMode(string name) {
        name =
            [
                "ECB", "CBC", "CFB"
            ]
    }

    /**
     * Miscellaneous objects that may raise a flag
     */
    predicate isMiscellaneousToBeFlagged(string name) {
        name =
            [
                "NACL", "SSH", "RAND", "RANDOM", "TLS", "SUBTLE", "X509"
            ]
    }
}

private import AlgorithmNames

// Adapted from CWE-327 CryptoLibraries

private newtype TCrpytographicAlgorithm =
BadBlockCipherMode(string name) {
    isDisallowedBlockCipherMode(name)
}


abstract class CryptographicAlgorithm extends TCrpytographicAlgorithm {
  string toString() { result = this.getName() }

  abstract string getName();

  bindingset[name]
  predicate matchesName(string name) {
      exists(name.regexpFind(".*" + this.getName() + ".*", _, _))
  }
}

class DisallowedBlockCipherMode extends BadBlockCipherMode, CryptographicAlgorithm {
    string name;
    DisallowedBlockCipherMode() { this = BadBlockCipherMode(name) }
    override string getName() { result = name }
}
