# jTrust

[![Build Status](https://travis-ci.com/Corilus/jtrust.svg?branch=master)](https://travis-ci.com/Corilus/jtrust)
[![Java CI with Maven](https://github.com/Corilus/jtrust/actions/workflows/maven.yml/badge.svg)](https://github.com/Corilus/jtrust/actions/workflows/maven.yml)

## Introduction

This project contains the source code tree of the jTrust library.

The source code is hosted at: https://github.com/e-Contract/jtrust

The Maven project site is hosted at e-contract.be: https://www.e-contract.be/sites/jtrust/

Issues can be reported via github: https://github.com/e-Contract/jtrust/issues

Also check out the eID Applet mailing list for announcements: https://groups.google.com/forum/#!forum/eid-applet


## Getting Started

A good entry point for using the jTrust project is the Maven project site.

https://www.e-contract.be/sites/jtrust/jtrust-lib/


## Requirements

The following is required for compiling the jTrust software:
* Oracle Java 1.8.0_232
* Apache Maven 3.6.3+


## Build

The project can be build via:

```shell
mvn clean install
```

## Releasing

```
mvn versions:set -DnewVersion=2.0.18
mvn clean verify
mvn versions:commit

git add .
git commit -m "Set release version to 2.0.18"
git push
git tag -a v2.0.18 -m "jtrust-2.0.18"
git push --tags

mvn versions:set -DnewVersion=2.0.19-SNAPSHOT
mvn versions:commit
git commit -m "Changed working version to 2.0.19-SNAPSHOT"
git push
```


## License

The license conditions can be found in the file: LICENSE.txt
