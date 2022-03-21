/**
 * @name Approved Hashing Expression
 * @description Part of a set of checks for cryptographic footprint - this is currently too broad and will likely result in duplicate results - trying to find usage of constants but not showing up
 * @kind problem
 * @precision very-high
 * @id go/cf-approved-hashing-expression
 * @tags security
 *       cryptographic-footprint
 * @security-severity 1.0
 * @problem.severity warning
 */

import go
import CryptoLibraries::AlgorithmNames

from ValueExpr ve
where isApprovedHashingAlgorithm(ve.toString().toUpperCase())
and not exists (
    Comment comment |
    comment.getLocation().getEndLine() = ve.getLocation().getStartLine() - 1
    and comment.getFile() = ve.getFile()
    and comment.getText().regexpMatch(nonCrypto())
)
select ve, "Possible use of " + ve.toString()