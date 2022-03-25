import hashlib

class foo:
    def sha256(self, stuff):
        return stuff

# FINDINGS
hashlib.sha256().hexdigest()
foo.sha256('stuff')
blah3 = foo.sha256('morestuff')

# NOT FINDING

blah2.bar()