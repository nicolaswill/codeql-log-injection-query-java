/**
 * @name Logging library configured insecurely
 * @description Insecurely configured logging libraries that do not make use of message encoding
 *              implicitly enable log injection attacks unless code-level encoding mitigations exist.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.8
 * @precision high
 * @id java/as/log-injection
 * @tags security
 *       external/cwe/cwe-117
 */

import java
import LogInjectionConfigFiles

from LoggerConfigLoggerElement logger, LoggerConfigAppenderElement appender, string reason
where
  appender = logger.getAppender().getReferencedAppender*() and
  appender.isUnsafe(reason)
select logger,
  "Logger $@ uses appender $@, which is vulnerable to log injection because " + reason + ".",
  logger, logger.getLoggerName(), appender, appender.getAppenderName()
