# COSE-JAVA Implementation [![Build Status](https://travis-ci.org/cose-wg/COSE-JAVA.svg?branch=master)](https://travis-ci.org/cose-wg/COSE-JAVA) [![Maven Central](https://img.shields.io/maven-central/v/com.augustcellars.cose/cose-java.svg?style=plastic)](https://search.maven.org/#search%7Cga%7C1%7Ccose-java)

This project is a JAVA implementation of the IETF CBOR Encoded Message Syntax (COSE).
There are currently two versions of the COSE document that can be read.
The most current work in progress draft can be found on github in the [cose-wg/cose-spec](https://cose-wg.github.io/cose-spec/) project.
The IETF also keeps a copy of the spec in the [COSE WG](https://tools.ietf.org/html/draft-ietf-cose-msg).

The project is implemented using Bouncy Castle for the crypto libraries and uses the PeterO CBOR library for its CBOR implementation.

## How to Install

Starting with version 0.9.0, the Java imlemention is available as an [artifact](https://search.maven.org/#search%7Cga%7C1%7Ccose-java) in the Central Repository.
To add this library to a Maven project, add the following to the `dependencies` section in your pom.xml file:

```xml
<dependency>
  <groupId>com.augustcellars.cose</groupId>
  <artifactId>cose-java</artifactId>
  <version>0.9.0</version>
</dependency>
```

In other Java-based environments, the library can be referred to by its group ID ('com.augustcellars.cose'), artifact ID ('cose-java'), and version, as given above.

## Documentation

Still need to figure this out.

## Contributing

Go ahead, file issues, make pull requests.  There is an automated build process that will both build and run the test suites on any requests.  These will need to pass, or have solid documentation about why they donot pass, before any pull request will be merged.

## Building

Currently setup to build in the NetBeans IDE.  Automated checking is performed using the [COSE Examples](https://github.com/cose-wg/Examples) as part of the suite.

The examples are located by the following method. 1) If 'c:\\Projects\\cose\\" exists then it uses that as the directory to look in for the examples. 2) It expects that the examples are in the same directory as the pom.xml file.
