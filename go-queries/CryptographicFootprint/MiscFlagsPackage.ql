/**
 * @name Miscellaneous Crypto Package
 * @description Part of a set of checks for cryptographic footprint
 * @kind problem
 * @precision very-high
 * @id go/cf-miscellaneous-crypto-package
 * @tags security
 *       cryptographic-footprint
 * @security-severity 1.0
 * @problem.severity warning
 */

import go
import CryptoLibraries::AlgorithmNames

from DataFlow::CallNode c
where isMiscellaneousToBeFlagged(c.getTarget().getPackage().getName().toUpperCase())
select c, "Detected " + c.getTarget().getName() + " from " + c.getTarget().getPackage().getPath()