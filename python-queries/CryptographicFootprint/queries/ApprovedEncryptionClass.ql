/**
 * @name Approved Encryption Class Check
 * @description Part of a set of checks for cryptographic footprint
 * @kind problem
 * @precision very-high
 * @id go/cf-approved-encryption-class
 * @tags security
 *       cryptographic-footprint
 * @security-severity 1.0
 * @problem.severity warning
 */

// Heavily adapted from existing work in CWE-327 and codeql python libraries
// This looks for broader, less specific usages

import python
import CryptoLibraries

from Class c, ApprovedEncryptionAlgorithm a
where a.matchesName(c.getName().toUpperCase())
select c, "Found declaration of class " + c.getName()