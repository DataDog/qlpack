/**
 * @name Go Mod Library Check
 * @description Part of a set of checks for cryptographic footprint.  Naively looks for usage of go crypto or openssl libraries.
 * @kind problem
 * @precision very-high
 * @id go/cf-mod-library-check
 * @tags security
 *       cryptographic-footprint
 * @security-severity 1.0
 * @problem.severity warning
 */

import go
import CryptoLibraries::AlgorithmNames

from GoModRequireLine gm
where gm.getPath().regexpMatch(".*crypto.*|.*openssl.*|.*kyber.*|.*kryptology.*")
and not exists (
    Comment comment |
    comment.getLocation().getEndLine() = gm.getLocation().getStartLine() - 1
    and comment.getFile() = gm.getFile()
    and comment.getText().regexpMatch(nonCrypto())
)
select gm, gm.getPath() + " version " + gm.getVersion()