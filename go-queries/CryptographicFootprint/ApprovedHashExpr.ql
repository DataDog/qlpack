/**
 * @name CF - Approved Hashing Expression
 * @description Part of a set of checks for cryptographic footprint - this is currently too broad and will likely result in duplicate results - trying to find usage of constants but not showing up
 * @kind problem
 * @precision very-high
 * @id go/cf-approved-hashing-expression
 * @tags security
 * @security-severity 1.0
 * @problem.severity warning
 */

import go
import CryptoLibraries::AlgorithmNames

from ValueExpr ve
where isApprovedHashingAlgorithm(ve.toString().toUpperCase())
select ve, "Possible use of " + ve.toString()