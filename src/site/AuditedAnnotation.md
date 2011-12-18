@Audited Annotation
===================

Introduction
------------


`@Audited` annotation writes an info message in the underlying SLF4J "`fr.xebia.audit`" logger each time the method is invoked

Table of Content
----------------

TODO

Usage pattern
-------------

Decorate the method you want to audit with a `@Audited` annotation like this:

````java
@Audited(message = "transferMoney(#{args[0].accountNumber}, #{args[1].accountNumber}, #{args[3].amount})")
public void transferMoney(Account from, Account to, Amount amount) throws BusinessException { ... }
````

The `message` attribute uses Spring Expression Language; available variables are:

 * `args`: the array of methods arguments,
 * `invokedObject`: the invoked object instance,
 * `throwned`: the exception if one has been throwned,
 * `returned`: the returned value.


Spring Framework Configuration
------------------------------

The `@Audited` annotation uses Spring AOP to intercept the method calls and uses Spring XML namespace configuration to ease its integration with a simple `<security-extras:audit-aspect />` in your Spring configuration file.

````xml
<beans ...
   xmlns:security-extras="http://www.xebia.fr/schema/xebia-spring-security-extras"
   xsi:schemaLocation="...
        http://www.xebia.fr/schema/xebia-spring-security-extras http://www.xebia.com/schema/security/xebia-spring-security-extras.xsd
        ">

   <!-- enable Spring AOP --> 
   <aop:aspectj-autoproxy/>

  <!-- activate the AutitAspect --> 
  <security-extras:audit-aspect />
    ...
</beans>
````

Note : If you face a `IllegalArgumentException: MetadataMBeanInfoAssembler does not support JDK dynamic proxies - export the target beans directly or use CGLIB proxies instead`, then you need tell AspectJ to use CGLib proxies adding the attribute `proxy-target-class="true"` like `<aop:aspectj-autoproxy proxy-target-class="true" />`.

The `@Audited` annotation relies on a standard [Spring Security](http://static.springsource.org/spring-security/)  configuration to get the name of the authenticated user name and its ip address (if used in a web application). 
It simply uses `SecurityContextHolder.getContext().getAuthentication()` and the `WebAuthenticationDetails` if present.

For more details about Spring Security configuration, please refer to the [documentation](http://static.springsource.org/spring-security/site/docs/3.0.x/reference/ns-config.html#ns-getting-started official). 

Generated Audit Messages
------------------------

Audit messages are generated in the SLF4J logger named `fr.xebia.audit` with the pattern:

````java
$date{yyyy/MM/dd-HH:mm:ss:SSS} ${message} [threw ${exception.toString()}] by ${spring-security.principal.name} [coming from ${spring-security.principal.ip}] in ${duration} ms
````

If an exception is throwned, the log message is emitted at the `WARN` level ; otherwise, the `INFO` level is used.

Sample of message for a `@Audited(message = "save(#{args[0].name}, #{args[0].email}): #{returned?.id}")`: 

 * In case of successful invocation
    ````java
2010-08-11T00:23:05.353+0200 save(John Smith, john.smith@xebia.fr): 324325 by ze-principal coming from 10.0.0.1 in 21 ms
````
 * In the method invocation throwned anexception
    ````java
2010-08-11T00:23:05.353+0200 save(John Smith, john.smith_at_xebia.fr): threw 'java.lang.IllegalArgumentException: invalid email' by ze-principal coming from 10.0.0.1 in 32 ms
````

Logging Framework Configuration
-------------------------------

The `@Audited` annotation relies on [SLF4J](http://www.slf4j.org/) to generate its audit messages. We like very much using the [LogBack](http://logback.qos.ch/)  implementation with its powerful feature of moving _rolled backed_ files in another folder but [Log4j](http://logging.apache.org/log4j/1.2/index.html) is also well suited for this task.

Note that the appender is not configured to append the date, the thread name or the log level, the audit aspect already appends the date and the thread and level are usually not necessary for auditing.

### Logback configuration sample

This Logback configuration fragment shows how to log "`fr.xebia.audit`" audit messages in a file named  "`my-application-audit.log`" that is rolled and zipped every night to a collect folder (`${LOGS_TO_COLLECT_FOLDER} `).

````xml
<configuration scan="true">
   ...
   <appender name="audit-file" class="ch.qos.logback.core.rolling.RollingFileAppender">
      <file>${LOGS_FOLDER}/my-application-audit.log</file>
      <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
         <fileNamePattern>${LOGS_TO_COLLECT_FOLDER}/my-application-audit.%d{yyyyMMdd-HHmm}.log.gzip</fileNamePattern>
      </rollingPolicy>
      <encoder>
         <pattern>%m %throwable{0}%n</pattern>
      </encoder>
   </appender>

   <logger name="fr.xebia.audit" additivity="false" level="TRACE">
      <appender-ref ref="audit-file" />
   </logger>
   ...
</configuration>
````

### Log4j configuration sample

This Log4j configuration fragment shows how to log "`fr.xebia.audit`" audit messages in a file named  "`my-application-audit.log`" that is rolled every night.

````
log4j.appender.auditfile=org.apache.log4j.DailyRollingFileAppender
log4j.appender.auditfile.datePattern='-'yyyyMMdd
log4j.appender.auditfile.file=${catalina.base}/logs/my-application-audit.log
log4j.appender.auditfile.layout=org.apache.log4j.EnhancedPatternLayout
log4j.appender.auditfile.layout.conversionPattern=%m %throwable{short}\n

log4j.logger.fr.xebia.audit=INFO, auditfile
````

Auditing without the @Audited annotation
----------------------------------------

In some cases, using the `@Audited` annotation is awkward (auditing in the middle of a method, building complex messages, etc) and it is easier to directly use the Java component like this :

 * Usage pattern:
    ````java
public void transferMoney(...) throws BusinessException {
   ...
   Auditor.audit("Tranfer " + amount + " from " + fromAccount + " to " + toAccount);
}
````
 * Emitted message format : `"$date{yyyy/MM/dd-HH:mm:ss:SSS} ${message} [throwing ${exception.toString()}] by ${spring-security.principal.name} [coming from ${spring-security.principal.ip}]"`
 * Sample of message: `"2010-08-11T00:23:05.353+0200 Transfer 1000 euros from account[12345] to account[9876] by ze-principal coming from 10.0.0.1"`
 * This annotation relies Spring Security to get the authenticated user name and its ip address
 * Logback and log4j configuration sample: see @Audited above

How to Integrate this library in your project
---------------------------------------------

There are different ways to integrate these features in your project:

 * Maven integration :

    ````xml
<project ...>
   <dependencies>
      <dependency>
         <groupId>fr.xebia.springframework</groupId>
         <artifactId>xebia-spring-security-extras</artifactId>
         <version>1.1.6</version>
      </dependency>
      ...
   </dependencies>
   ...
</project>
````

 * Download the jar [xebia-spring-security-extras-1.1.6.jar](http://repo1.maven.org/maven2/fr/xebia/springframework/xebia-spring-security-extras/1.1.6/xebia-spring-security-extras-1.1.6.jar) ([sources](http://repo1.maven.org/maven2/fr/xebia/springframework/xebia-spring-security-extras/1.1.6/xebia-spring-security-extras-1.1.6-sources.jar)),
 * Get the source from svn, modify it if needed and add it to your project. The source is available under the Open Source licence [Apache Software Licence 2](http://www.apache.org/licenses/LICENSE-2.0) at https://github.com/xebia-france/xebia-spring-security-extras .


Implementation decisions and details
------------------------------------

### Choosing a logging framework to handle audit messages

Audit messages are outputted to a logging framework. Here are the pros and cons we evaluated :

 * Cons :
  * From a theoretical standpoint, audit and log are different things and should be isolated,
  * From a practical standpoint, it is dangerous to say to mix audit and logs configurations. Someone could mistakenly disable all the audit misconfiguring the logging framework ; this could occur during a troubleshooting session during which the ops team would have to enable/disable log messages.
 * Pros :
  * Auditing in files is simple, stupid and efficient ; much more than doing it in a database or any other sophisticated system,
  * Auditing can involve writing a large volume of messages (> 1 Go / day / server) and logging frameworks are very well suited for these write-intensive tasks,
  * Logging frameworks offer sophisticated file management mechanisms (safe rolling, compression, moving, etc),
  * Despite the risk of misconfiguring the logging framework and loosing the audit messages, we have never seen such a mistake ; logging framework configuration file can be simple enough to prevent such mistake.

As a Java logging framework, we chose the [SLF4J](http://www.slf4j.org/) facade for the following reasons :

 * it works with [LogBack](http://logback.qos.ch/) which is our preferred logging framework,
 * it works with [Log4j](http://logging.apache.org/log4j/) that is very frequently used and is well suited for auditing.

### Declarative approach and AOP

We decided to use an annotation based declarative approach that would be homogeneous with the Spring 2.5+ & Java EE 5+ programming styles with all their annotations (security - `@RolesAllowed`), transaction - `@Transactional`), etc ).

Developers would just have to decorate their methods with a `@Audited` annotation.

`@Audited` annotated methods are intercepted at runtime thanks to [ Spring AOP](http://static.springsource.org/spring/docs/3.0.x/spring-framework-reference/html/aop.html) and [AspectJ's](http://www.eclipse.org/aspectj/)  [@Around](http://www.eclipse.org/aspectj/doc/released/aspectj5rt-api/org/aspectj/lang/annotation/Around.html) annotation (see [AuditAspect.java](https://github.com/xebia-france/xebia-spring-security-extras/blob/ee0fd5095d854f6c0e75fba21b6a9c697be56b02/src/main/java/fr/xebia/audit/AuditAspect.java)).

### Expression language based messages

The smoothest technique we found to allow developer to build audit messages composed with parameters/returned-value/throwned-exception of audited methods was to exposed these in an expression language. This approach was consistent with the increasing role of expression languages in java frameworks (see Spring Expression Language, etc).
An other approach would have been to follow the [Inspektr](https://github.com/dima767/inspektr) way and ask developers to develop one "message builder class" per audited method.

The performance impact of the expression language evaluation at each invocation proved to be negligible trying with both [Apache Commons JEXL](http://commons.apache.org/jexl/) and [Spring Expression Language](http://static.springsource.org/spring/docs/3.0.5.RELEASE/spring-framework-reference/html/ch07.html) . 

The first versions of the @Audited annotations (2008) used JEXL, when we decided to put the version 3 of Spring Framework as a pre requisite, we could then switch to Spring Expression Language to offer a more homogeneous integration with the Spring Framework and lower the number of dependencies.

The `@Audited` annotation uses [Spring Expression Language's](http://static.springsource.org/spring/docs/3.0.0.M3/spring-framework-reference/html/ch07.html) [SpelExpressionParser](http://static.springsource.org/spring/docs/3.0.x/javadoc-api/org/springframework/expression/spel/standard/SpelExpressionParser.html)  (see [AuditAspect.java](https://github.com/xebia-france/xebia-spring-security-extras/blob/ee0fd5095d854f6c0e75fba21b6a9c697be56b02/src/main/java/fr/xebia/audit/AuditAspect.java)).

### XML Namespace based Spring configuration

Spring XML namespace based configuration is performed thanks to Spring's [BeanDefinitionParser](http://static.springsource.org/spring/docs/3.0.0.M3/spring-framework-reference/html/apbs04.html) (see [AuditAspectDefinitionParser.java](https://github.com/xebia-france/xebia-spring-security-extras/blob/d6875ec63a8b674765721755eb358b3419d45255/src/main/java/fr/xebia/springframework/security/config/AuditAspectDefinitionParser.java )).