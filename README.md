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
  <version>0.9.7</version>
</dependency>
```

In other Java-based environments, the library can be referred to by its group ID ('com.augustcellars.cose'), artifact ID ('cose-java'), and version, as given above.

## Cryptographic Providers

Starting with version 0.9.7, the code was modified so that it only uses the JAVA cryptogprahic provider infrastructure rather than directly relying on the BouncyCastle implementations of these algorithms.  There are two implications of these changes that people need to be aware of at this time.

* By default JAVA is installed with a limited set of enabled cryptographic algorithms. This can be noted by the fact that an algorithm is supported, but that not all key sizes for the algorithm are enabled.  In order to deal with this one needs to install the 'Java Cryptographic Extension Unlimited Strenght Jusrisdiction Policy Files' for your version of JAVA runtime.  An example of this for JAVA 8 is (http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html).

* Some modes and algorithms are not generally supported by the default Cryptographic Provider.  One example of this is the CCM mode for AES.  Getting these algorithms to work requires that a new provider be installed as part of the application so that it is available for this module.  Sample code that installs the BouncyCastle provider is:

```java
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;
import java.security.Provider;

public class InstallBouncyCastle {
   private static final Provider PROVIDER;
   
   public static void installProvider() throws Exception {
       if (PROVIDER != null) return;
       PROVIDER = new BouncyCastleProvider();
       Security.insertProviderAt(PROVIDER, 1);
   }

   public static void removeProvider() throws Exception {
       Security.removeProvider(PROVIDER.getName());
       PROVIDER = null;
}
```

## Documentation

Still need to figure this out.

## Contributing

Go ahead, file issues, make pull requests.  There is an automated build process that will both build and run the test suites on any requests.  These will need to pass, or have solid documentation about why they do not pass, before any pull request will be merged.

## Building

Currently setup to build in the NetBeans IDE.  Automated checking is performed using the [COSE Examples](https://github.com/cose-wg/Examples) as part of the suite.

The examples are located by the following method. 1) If 'c:\\Projects\\cose\\" exists then it uses that as the directory to look in for the examples. 2) It expects that the examples are in the same directory as the pom.xml file.
