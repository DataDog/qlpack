/**
 * @name Disallowed Password Hashing Package
 * @description Part of a set of checks for cryptographic footprint
 * @kind problem
 * @precision very-high
 * @id go/cf-disallowed-password-package
 * @tags security
 *       cryptographic-footprint
 * @security-severity 1.0
 * @problem.severity warning
 */

import go
import CryptoLibraries::AlgorithmNames

from DataFlow::CallNode c, Comment comment
where isDisallowedPasswordHashingAlgorithm(c.getTarget().getPackage().getName().toUpperCase())
and comment.getLocation().getStartLine() = c.getStartLine() - 1
and not comment.getText().regexpMatch(nonCrypto())
select c, "Detected " + c.getTarget().getName() + " from " + c.getTarget().getPackage().getPath()