/**
 * @name Approved Encryption Method
 * @description Part of a set of checks for cryptographic footprint
 * @kind problem
 * @precision very-high
 * @id go/cf-approved-encryption-method
 * @tags security
 *       cryptographic-footprint
 * @security-severity 1.0
 * @problem.severity warning
 */

import go
import CryptoLibraries::AlgorithmNames

from DataFlow::CallNode c
where isApprovedEncryptionAlgorithm(c.getCalleeName().toUpperCase())
and not exists (
    Comment comment |
    comment.getLocation().getEndLine() = c.getStartLine() - 1
    and comment.getFile() = c.getFile()
    and comment.getText().regexpMatch(nonCrypto())
)
select c, "Detected " + c.getCalleeName()
+ " from " + c.getTarget().getPackage().getPath()
