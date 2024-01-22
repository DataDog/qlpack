import hashlib

class foo:
    def sha256(self, stuff):
        return stuff

class bleh:
    def bar():
        return "hm"

# FINDINGS
hashlib.sha256().hexdigest()
foo.sha256('stuff')
blah = foo.sha256('morestuff')

# NOT FINDING
bleh.bar()