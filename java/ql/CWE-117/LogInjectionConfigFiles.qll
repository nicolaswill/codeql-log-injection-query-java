/** Provides classes and predicates related to vulnerable logging library configurations. */

import java
import semmle.code.configfiles.ConfigFiles

/**
 * An XML config file for a logging library (currently supports `log4j2.xml` and `logback.xml`).
 */
abstract class LoggerConfigFile extends XmlFile { }

/**
 * An appender element in a logging library config file, specifying how to write log messages.
 * Appenders can potentially define encodings or layouts that mitigate log injection vulnerabilities.
 */
abstract class LoggerConfigAppenderElement extends XmlElement {
  /** Holds if the appender is unsafe, and binds `reason` to a description of why it is unsafe. */
  abstract predicate isUnsafe(string reason);

  /** Gets the type of the appender, e.g. `Console` or `Http`. */
  abstract string getAppenderType();

  /** Gets the name of the appender, as specified in the config file. */
  abstract string getAppenderName();

  /** Gets the referenced appender if this appender has a reference to another appender (e.g. `AsyncAppender`). */
  LoggerConfigAppenderElement getReferencedAppender() { result = this }
}

/**
 * A logger element in a logging library config file, defining when and how messages are logged.
 * Loggers determine how messages are logged by referencing one or more appender elements.
 */
abstract class LoggerConfigLoggerElement extends XmlElement {
  /** Gets the appender referenced by the logger. */
  abstract LoggerConfigAppenderElement getAppender();

  /** Gets the name of the logger. */
  abstract string getLoggerName();
}

/**
 * A `log4j2.xml` configuration file.
 * This class excludes generated files in `target/classes`.
 */
class Log4J2XmlConfigFile extends LoggerConfigFile {
  Log4J2XmlConfigFile() {
    this.getBaseName() = "log4j2.xml" and
    not this.getAbsolutePath().matches("%/target/classes/log4j2.xml")
    // TODO: add support for xi:include
  }
}

/**
 * A `logback.xml` configuration file.
 * This class excludes generated files in `target/classes`.
 */
class LogbackConfigFile extends LoggerConfigFile {
  LogbackConfigFile() {
    this.getBaseName() = "logback.xml" and
    not this.getAbsolutePath().matches("%/target/classes/logback.xml")
    // TODO: add support for include
  }
}

/** Holds if the given log4j2 `pattern` layout is unsafe and binds `reason` to a description of why it is unsafe. */
bindingset[pattern]
predicate isUnsafeLog4j2PatternLayout(string pattern, string reason) {
  pattern.regexpMatch(".*(?<!%enc\\{)%(?:m|msg|message)\\b.*") and
  reason = "the pattern does not contain a message encoding"
  or
  pattern.regexpMatch(".*%enc\\{%(?:m|msg|message)\\}\\{CRLF\\}.*") and
  reason = "the pattern contains only CRLF message encoding"
}

class Log4J2Appender extends LoggerConfigAppenderElement {
  Log4J2Appender() {
    this.getFile() instanceof Log4J2XmlConfigFile and
    this.getParent().getName() = "Appenders"
  }

  override string getAppenderType() { result = this.getName() }

  override string getAppenderName() { result = this.getAttribute("name").getValue() }

  override predicate isUnsafe(string reason) {
    isUnsafeLog4j2PatternLayout(this.getAChild("PatternLayout").getAttribute("pattern").getValue(),
      reason)
    or
    // Appenders with default pattern layouts:
    // https://logging.apache.org/log4j/2.x/manual/appenders.html
    this.getAppenderType() =
      [
        "Console", "FileAppender", "MemoryMappedFileAppender", "RandomAccessFileAppender",
        "RollingFileAppender", "RollingRandomAccessFileAppender", "ZeroMQ", "JeroMQ"
      ] and
    // TODO: improve this heuristic check for layout names
    not this.getAChild().getName().matches("%Layout") and
    reason = "the appender uses the implicit default pattern layout"
  }
}

class Log4J2Logger extends LoggerConfigLoggerElement {
  Log4J2Logger() {
    this.getFile() instanceof Log4J2XmlConfigFile and
    this.getParent().getName() = "Loggers"
  }

  override string getLoggerName() {
    result = this.getAttribute("name").getValue()
    or
    this.getName() = "Root" and
    result = "Root"
  }

  override Log4J2Appender getAppender() {
    result.getFile() = this.getFile() and
    result.getAppenderName() = this.getAChild("AppenderRef").getAttribute("ref").getValue()
  }
}

private LogbackAppender getLogbackAppenderFromAppenderRef(XmlElement ref) {
  // TODO: the appender may be in an imported file
  result.getFile() = ref.getFile() and
  result.getAppenderName() = ref.getAChild("appender-ref").getAttribute("ref").getValue()
}

class LogbackAppender extends LoggerConfigAppenderElement {
  LogbackAppender() {
    this.getFile() instanceof LogbackConfigFile and
    this.getParent().getName() = "configuration" and
    this.getName() = "appender"
  }

  override string getAppenderType() { result = this.getName() }

  override string getAppenderName() { result = this.getAttribute("name").getValue() }

  override predicate isUnsafe(string reason) {
    (
      // the default pattern layout is `ch.qos.logback.classic.encoder.PatternLayoutEncoder`
      not exists(this.getAChild("encoder").getAttribute("class"))
      or
      this.getAChild("encoder").getAttribute("class").getValue() =
        "ch.qos.logback.classic.encoder.PatternLayoutEncoder"
    ) and
    reason = "the appender uses the pattern layout encoder"
  }

  override LogbackAppender getReferencedAppender() {
    result = getLogbackAppenderFromAppenderRef(this)
  }
}

class LogbackLogger extends LoggerConfigLoggerElement {
  LogbackLogger() {
    this.getFile() instanceof LogbackConfigFile and
    this.getParent().getName() = "configuration" and
    this.getName() = ["logger", "root"]
  }

  override string getLoggerName() {
    result = this.getAttribute("name").getValue()
    or
    this.getName() = "root" and
    result = "root"
  }

  override LogbackAppender getAppender() { result = getLogbackAppenderFromAppenderRef(this) }
}
