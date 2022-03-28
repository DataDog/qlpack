/**
 * @name Approved Hashing Class Check
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
import CryptoLibraries

// Here we're using the regex check because unlike methods it's less likely to run into false positives
// As an example, doing the same in functions quickly yields DSA matching "call_soon_threadsafe" methods

from Class c, ApprovedHashAlgorithm a
where a.matchesName(c.getName().toUpperCase())
select c, "Found declaration of class " + c.getName()