Introduction
============

Spring Security addons. This code is not provided by SpringSource nor by the Spring Framework Project.

Audit
=====

@Audited
--------

See [AuditedAnnotation](http://code.google.com/p/xebia-france/wiki/AuditedAnnotation). Simply add declarative auditing in your application using an `@Audited` annotation like this:

````
@Audited(message = "transferMoney(#{args[0].accountNumber}, #{args[1].accountNumber}, #{args[3].amount})")
public void transferMoney(Account from, Account to, Amount amount) throws BusinessException { ... }
````

How to Integrate this library in your project
=============================================

There are different ways to integrate these features in your project:
 * Maven integration :

````
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

  The artifact is deployed on [https://oss.sonatype.org/content/repositories/public/fr/xebia/springframework/xebia-spring-security-extras/1.1.6/ Sonatype OSS repo] and should soon be synced on http://repo1.maven.org/ (as of 2011/11/13).
 * Download the jar [xebia-spring-security-extras-1.1.6.jar](http://repo1.maven.org/maven2/fr/xebia/springframework/xebia-spring-security-extras/1.1.6/xebia-spring-security-extras-1.1.6.jar) ([sources](http://repo1.maven.org/maven2/fr/xebia/springframework/xebia-spring-security-extras/1.1.6/xebia-spring-security-extras-1.1.6-sources.jar)),
 * Get the source from svn, modify it if needed and add it to your project. The source is available under the Open Source licence [Apache Software Licence 2](http://www.apache.org/licenses/LICENSE-2.0) at https://github.com/xebia-france/xebia-spring-security-extras/ .

Developers
==========

 * Source : https://github.com/xebia-france/xebia-spring-security-extras/