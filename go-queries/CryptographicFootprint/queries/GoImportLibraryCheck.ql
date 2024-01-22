/**
 * @name Go Import Library Check
 * @description Reveals usages of go/crypto and a variety of go openssl for cryptographic footprint
 * @kind problem
 * @precision very-high
 * @id go/cf-import-library-check
 * @tags security
 *       cryptographic-footprint
 * @security-severity 1.0
 * @problem.severity warning
 */

import go
import CryptoLibraries::AlgorithmNames

from ImportSpec i
where i.getPath().regexpMatch("(golang.org/x/)?crypto/.*|.*openssl.*|.*kyber.*|.*kryptology.*")
and not exists (
    Comment comment |
    comment.getLocation().getEndLine() = i.getLocation().getStartLine() - 1
    and comment.getFile() = i.getFile()
    and comment.getText().regexpMatch(nonCrypto())
)
select i, "Possible crypto import: " + i.getPath()
