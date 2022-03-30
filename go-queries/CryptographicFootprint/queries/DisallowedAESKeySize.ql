/**
 * @name Disallowed AES Key Size
 * @description Part of a set of checks for cryptographic footprint
 * @kind problem
 * @precision very-high
 * @id go/cf-disallowed-aes-key-size
 * @tags security
 *       cryptographic-footprint
 * @security-severity 1.0
 * @problem.severity warning
 */

import go

// Credit where it's due - adapted from CWE-326
class AESKeyTrackingConfiguration extends DataFlow::Configuration {
    AESKeyTrackingConfiguration() { this = "AESKeyTrackingConfiguration"}

    override predicate isSource(DataFlow::Node source) { source.getStringValue().length() < 16 }

    override predicate isSink(DataFlow::Node sink) {
        exists(DataFlow::CallNode c |
            sink = c.getArgument(0) and
            c.getTarget().hasQualifiedName("crypto/aes", "NewCipher")
        )
    }

    // There's a complex barrier guard implementation of this in CWE-326,
    // but I don't want to cargo cult something I understand even less
}

from AESKeyTrackingConfiguration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, "Detected " + sink.toString() + " from " + sink.getFile().getRelativePath() " where the size of this AES key should be at least 16 bytes (128 bits)"