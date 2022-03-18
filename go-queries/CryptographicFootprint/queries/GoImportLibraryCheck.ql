/**
 * @name Go Import Library Check
 * @description Reveals usages of go/crypto and a variety of go openssl for cryptographic footprint
 * @kind problem
 * @precision very-high
 * @id go/cf-import-library-check
 * @tags security
 *       cryptographic-footprint
 * @security-severity 1.0
 * @problem.severity warning
 */

import go

from ImportSpec i
where i.getPath().regexpMatch("crypto/.*|.*openssl.*")
select i, "Possible crypto import: " + i.getPath()
