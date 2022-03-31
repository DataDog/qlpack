import cryptography

class foo:
    def rsa(self, stuff):
        return stuff

class bleh:
    def bar():
        return "hm"

# FINDINGS
cryptography.hazmat.primitives.ciphers.algorithms.AES("1234567890123456")
foo.rsa('stuff')
blah = foo.rsa('morestuff')

# NOT FINDING
bleh.bar()