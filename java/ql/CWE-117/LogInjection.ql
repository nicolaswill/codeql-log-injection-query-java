/**
 * @name Log Injection from non-encoded string
 * @description Building log entries from non-encoded data may allow
 *              injection of forged or malicious log entries by users.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.8
 * @precision high
 * @id java/as/log-injection
 * @tags security
 *       external/cwe/cwe-117
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.LogInjection
import DataFlow::PathGraph
import LogInjectionConfigFiles

abstract private class LogInjectionSanitizerNode extends DataFlow::Node { }

/**
 * Copied from `DefaultLogInjectionSanitizer` in LogInjection.qll.
 */
class NonStringLogInjectionSanitizer extends LogInjectionSanitizerNode {
  NonStringLogInjectionSanitizer() {
    this.getType() instanceof BoxedType or
    this.getType() instanceof PrimitiveType or
    this.getType() instanceof NumericType
  }
}

/**
 * A string argument to a Base64- or URL-encoding method call.
 */
class URLEncodeLogInjectionSanitizer extends LogInjectionSanitizerNode {
  URLEncodeLogInjectionSanitizer() {
    exists(MethodAccess ma |
      ma.getMethod()
          .hasQualifiedName(["java.util", "java.net", "org.springframework.util"],
            ["Base64$Encoder", "Base64", "Base64Utils", "URLEncoder"],
            [
              "encode", "encodeToString", "encodeBase64", "encodeBase64Chunked",
              "encodeBase64String", "encodeBase64URLSafe", "encodeBase64URLSafeString"
            ])
    |
      this.asExpr() = ma.getArgument(0)
    )
  }
}

/**
 * A logging method access that is defined to perform structured logging.
 */
class CFStructuredLoggingSink extends DataFlow::Node {
  CFStructuredLoggingSink() {
    this instanceof LogInjectionSink and
    exists(MethodAccess ma |
      ma.getAnArgument() = this.asExpr() and
      (
        ma.getMethod().getDeclaringType().getQualifiedName() =
          ["org.slf4j.Logger", "org.apache.logging.log4j"] and
        exists(Log4J2Logger logger | not logger.getAppender().getReferencedAppender*().isUnsafe(_))
        or
        // logback sinks not defined in models-as-data but slf4j should cover most cases
        ma.getMethod().getDeclaringType().getQualifiedName() = ["org.slf4j.Logger"] and
        exists(LogbackLogger logger | not logger.getAppender().getReferencedAppender*().isUnsafe(_))
      )
    )
  }
}

class LogInjectionConfiguration extends TaintTracking::Configuration {
  LogInjectionConfiguration() { this = "LogInjectionConfiguration" }

  override predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof LogInjectionSink and
    // heuristic compromise to exclude results that are not unstructured logging calls:
    // exclude sinks that are arguments to slf4j/log4j logging calls that are defined to perform structured logging
    not sink instanceof CFStructuredLoggingSink
  }

  override predicate isSanitizer(DataFlow::Node node) { node instanceof LogInjectionSanitizerNode }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    any(LogInjectionAdditionalTaintStep c).step(node1, node2)
  }
}

from LogInjectionConfiguration config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "This log entry depends on a $@.", source.getNode(),
  "user-provided value"
