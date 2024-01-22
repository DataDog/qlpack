/**
 * @name Approved Password Hashing Method
 * @description Part of a set of checks for cryptographic footprint
 * @kind problem
 * @precision very-high
 * @id go/cf-approved-password-method
 * @tags security
 *       cryptographic-footprint
 * @security-severity 1.0
 * @problem.severity warning
 */

import go
import CryptoLibraries::AlgorithmNames

from DataFlow::CallNode c
where isApprovedPasswordHashingAlgorithm(c.getCalleeName().toUpperCase())
and not exists (
    Comment comment |
    comment.getLocation().getEndLine() = c.getStartLine() - 1
    and comment.getFile() = c.getFile()
    and comment.getText().regexpMatch(nonCrypto())
)
select c, "Detected " + c.getTarget().getName() + " from " + c.getTarget().getPackage().getPath()