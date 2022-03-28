/**
 * @name Approved Hashing Method Check
 * @description Part of a set of checks for cryptographic footprint
 * @kind problem
 * @precision very-high
 * @id go/cf-approved-hashing
 * @tags security
 *       cryptographic-footprint
 * @security-severity 1.0
 * @problem.severity warning
 */

// Heavily adapted from existing work in CWE-327 and codeql python libraries
// This looks for broader, less specific usages

import python
import CryptoLibraries::AlgorithmNames

// Unfortunately, I'm having to split this into a test check for direct functions
// and a check for attributes because somehow method calls off modules are being interpreted as attributes?

from Call c
where isApprovedHashingAlgorithm(c.getASubExpression().(Attribute).getAttr().toUpperCase())
select c, "Found a usage of method " + c.getASubExpression().(Attribute).getAttr()