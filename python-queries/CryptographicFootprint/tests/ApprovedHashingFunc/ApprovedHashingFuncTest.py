class sha256:
    def bar(self, stuff):
        return stuff

# FINDINGS

blah2 = sha256()
sha256()

# NOT A FINDING

blah2.bar()