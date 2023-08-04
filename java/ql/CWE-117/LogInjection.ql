/**
 * @name Log Injection from non-encoded string
 * @description Building log entries from non-encoded data may allow
 *              insertion of forged log entries by malicious users.
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
import semmle.code.configfiles.ConfigFiles
import DataFlow::PathGraph

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
 * Returns the value of the `packages` attribute of a `log4j2.xml` config file.
 *
 * Example `log4j2.xml` config file:
 * ```
 *  <?xml version="1.0" encoding="UTF-8"?>
 *  <Configuration status="warn" strict="true"
 *  packages="com.sap.hcp.cf.log4j2.converter,com.sap.hcp.cf.log4j2.layout">
 *  ...
 *  ```
 *
 * For the above example config, this method returns `"com.sap.hcp.cf.log4j2.converter,com.sap.hcp.cf.log4j2.layout"`.
 */
string getLog4j2ConfigPackages() {
  exists(XmlFile config |
    config.getBaseName() = "log4j2.xml" and
    result = config.getAChild("Configuration").getAttribute("packages").getValue()
  )
}

/**
 * Returns the value of the `class` attribute of an `appender` element of a `logback.xml` config file.
 *
 * Example `logback.xml` config file:
 * ```
 * <?xml version="1.0" encoding="UTF-8"?>
 * <!DOCTYPE xml>
 * <configuration debug="false" scan="false">
 *    <turboFilter class="com.sap.hcp.cf.logback.filter.CustomLoggingTurboFilter" />
 *    <!-- write logs to console -->
 *    <appender name="STDOUT-JSON" class="ch.qos.logback.core.ConsoleAppender">
 *        <!-- encode and enrich full message with the required fields/tags -->
 *        <encoder class="com.sap.hcp.cf.logback.encoder.JsonEncoder" />
 *  ...
 *  ```
 *
 * For the above example config, this method returns `"com.sap.hcp.cf.logback.encoder.JsonEncoder"`.
 */
string getLogbackEncoderConfig() {
  exists(XmlFile config |
    config.getBaseName() = "logback.xml" and
    result =
      config
          .getAChild("configuration")
          .getAChild("appender")
          .getAChild("encoder")
          .getAttribute("class")
          .getValue()
  )
}

/**
 * A logging call that is defined to perform structured logging with
 * Java Logging Support for Cloud Foundry (https://github.com/SAP/cf-java-logging-support).
 * Note: `cf-java-logging-support` is one of many libraries that provide structured logging,
 * but is the only library currently modeled by this query. This query should be extended.
 */
class CFStructuredLoggingSink extends DataFlow::Node {
  CFStructuredLoggingSink() {
    this instanceof LogInjectionSink and
    exists(MethodAccess ma |
      ma.getAnArgument() = this.asExpr() and
      (
        ma.getMethod().getDeclaringType().getQualifiedName() =
          ["org.sl4j.Logger", "org.apache.logging.log4j"] and
        getLog4j2ConfigPackages().matches("%com.sap.hcp.cf.log4j2.layout%")
        or
        // logback sinks not defined in models-as-data but slf4j should cover most cases
        ma.getMethod().getDeclaringType().getQualifiedName() = ["org.slf4j.Logger"] and
        getLogbackEncoderConfig().matches("%com.sap.hcp.cf.logback.encoder.%")
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
