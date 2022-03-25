/**
 * @name Approved Hashing "Attribute" Check
 * @description Part of a set of checks for cryptographic footprint
 * @kind problem
 * @precision very-high
 * @id go/cf-approved-hashing
 * @tags security
 *       cryptographic-footprint
 * @security-severity 1.0
 * @problem.severity warning
 */

// While we could adapt work from CWE-327, this looks for more general rules and usages there
// Heavily adapted from existing work in CWE-327 and codeql python libraries

import python
import CryptoLibraries::AlgorithmNames

// Unfortunately, I'm having to split this into a test check for direct functions
// and a check for attributes because somehow method calls off modules are being interpreted as attributes?

from Call c
where isApprovedHashingAlgorithm(c.getASubExpression().(Attribute).getAttr().toUpperCase())
select c, "Found a usage of " + c.getASubExpression().(Attribute).getAttr()
