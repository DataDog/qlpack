/**
 * @name Approved Hashing
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

import python
import semmle.python.Concepts
import CryptoLibraries::AlgorithmNames

from Cryptography::CryptographicOperation operation, Cryptography::CryptographicAlgorithm algorithm
where
  algorithm = operation.getAlgorithm() and
  algorithm instanceof Cryptography::HashingAlgorithm and
  isApprovedHashingAlgorithm(algorithm.getName())
select operation,
  "Pointing out usage of " + algorithm.getName()