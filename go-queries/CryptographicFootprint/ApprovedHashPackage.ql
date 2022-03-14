/**
 * @name CF - Approved Hashing Package
 * @description Part of a set of checks for cryptographic footprint
 * @kind problem
 * @precision very-high
 * @id go/cf-approved-hashing-package
 * @tags security
 * @security-severity 1.0
 * @problem.severity warning
 */

import go
import CryptoLibraries::AlgorithmNames

from DataFlow::CallNode c
where isApprovedHashingAlgorithm(c.getTarget().getPackage().getName().toUpperCase())
select c, "Detected " + c.getTarget().getName() + " from " + c.getTarget().getPackage().getPath()