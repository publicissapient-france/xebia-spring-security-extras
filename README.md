Introduction
============

Spring Security addons. This code is not provided by SpringSource nor by the Spring Framework Project.

Audit
=====

@Audited
--------

See [AuditedAnnotation](wiki/AuditedAnnotation). Simply add declarative auditing in your application using an `@Audited` annotation like this:

````java
@Audited(message = "transferMoney(#{args[0].accountNumber}, #{args[1].accountNumber}, #{args[3].amount})")
public void transferMoney(Account from, Account to, Amount amount) throws BusinessException { ... }
````

How to Integrate this library in your project
=============================================

See [installation page](https://github.com/xebia-france/xebia-spring-security-extras/wiki/Installation)

Developers
==========

 * Source : https://github.com/xebia-france/xebia-spring-security-extras/