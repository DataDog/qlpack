/**
 * @name Disallowed Block Cipher Mode
 * @description Part of a set of checks for cryptographic footprint
 * @kind problem
 * @precision very-high
 * @id go/cf-disallowed-block-cipher
 * @tags security
 *       cryptographic-footprint
 * @security-severity 1.0
 * @problem.severity warning
 */

import go
import CryptoLibraries

from DisallowedBlockCipherMode cipher, DataFlow::CallNode c
where cipher.matchesName(c.getCalleeName().toUpperCase())
select c, "Detected " + c.getCalleeName() + " from " + c.getTarget().getPackage().getPath() + " is a disallowed block cipher"