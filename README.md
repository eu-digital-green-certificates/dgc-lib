<h1 align="center">
    EU Digital Green Certificates Lib
</h1>

<p align="center">
    <a href="https://sonarcloud.io/dashboard?id=eu-digital-green-certificates_dgc-lib" title="Quality Gate Status"><img src="https://sonarcloud.io/api/project_badges/measure?project=eu-digital-green-certificates_dgc-lib&metric=alert_status"></a>
    <a href="/../../commits/" title="Last Commit"><img src="https://img.shields.io/github/last-commit/eu-digital-green-certificates/dgc-lib?style=flat"></a>
    <a href="/../../issues" title="Open Issues"><img src="https://img.shields.io/github/issues/eu-digital-green-certificates/dgc-lib?style=flat"></a>
    <a href="./LICENSE" title="License"><img src="https://img.shields.io/badge/License-Apache%202.0-green.svg?style=flat"></a>
</p>

<p align="center">
  <a href="#development">Development</a> •
  <a href="#Usage">Usage</a> •
  <a href="#documentation">Documentation</a> •
  <a href="#support-and-feedback">Support</a> •
  <a href="#how-to-contribute">Contribute</a> •
  <a href="#contributors">Contributors</a> •
  <a href="#licensing">Licensing</a>
</p>

## About

This repository contains the source code of the Digital Green Certificates Library.

The DGC Lib contains shared functionality such as encoding, decoding and connecting to
the [DGCG](https://github.com/eu-digital-green-certificates/dgc-gateway).

## Usage

Include as Maven Dependency in pom.xml

```xml

<dependencies>
    <dependency>
        <groupId>eu.europa.ec.dgc</groupId>
        <artifactId>dgc-lib</artifactId>
        <version>1.0.0-SNAPSHOT</version>
    </dependency>
    ...
</dependencies>
```

### Authenticating to GitHub Packages

**Attention:**
GitHub does not allow anonymous access to it's package registry. You need to authenticate in order to use the dgc-lib artefact provided by us. 
Therefore you need to authenticate to [GitHub Packages](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-apache-maven-registry)
The following steps need to be performed

- Create [PAT](https://docs.github.com/en/github/authenticating-to-github/creating-a-personal-access-token) with scopes:
  - `read:packages` for downloading packages
- Copy/Augment `~/.m2/settings.xml` with the contents of `settings.xml` present in this repository (or in the DGC repository you are trying to build)
  - Replace `${app.packages.username}` with your github username
  - Replace `${app.packages.password}` with the generated PAT

## Development

### Build

Whether you cloned or downloaded the 'zipped' sources you will either find the sources in the chosen checkout-directory
or get a zip file with the source code, which you can expand to a folder of your choice.

In either case open a terminal pointing to the directory you put the sources in. The local build process is described
afterwards depending on the way you choose.

#### Maven based build

Building this project is done with maven.

```shell
mvnw install
```

Will download all required dependencies, build the project and stores the artifact in your local repository.

## Documentation

The following chapter describes the features of dgc-lib and how to use them.

### DGCG Connector

The dgc-lib provides a Spring-Boot ready connector for communicating with DGC Gateway. The connector has two core
functions:

#### Trusted Certificate Download

To download certificates from DGCG you just have to inject the ```DgcGatewayDownloadConnector``` and call the method
```getTrustedCertificates```. This method will check if a cached version of the downloaded certificates already exists.
The maximum age of the cache can be configured via properties. If the cache is too old or does not exist the connector
will call the API of DGC Gateway for Trusted Certificates.

The connector will do the following checks on downloaded certificates:

* TrustAnchor check of downloaded CSCA
* TrustAnchor check of downloaded Upload Certificates
* Check that DSC is issued by a trusted CSCA
* Check that DSC is signed by a trusted Upload Certificate

The validated list will be returned. In order to connect to DGC Gateway and do all the validating stuff the following
configuration is required:

```yml
dgc:
  gateway:
    connector:
      enabled: true
      endpoint: https://dgcg.example.org
      proxy:
        enabled: false
        host:
        port: -1
      max-cache-age: 300
      tls-trust-store:
        password: dgcg-p4ssw0rd
        path: classpath:tls-truststore.jks
      tls-key-store:
        alias: mtls_private_cert
        password: dgcg-p4ssw0rd
        path: /var/lib/ssl/mtls.jks
      trust-anchor:
        alias: ta_tst
        password: dgcg-p4ssw0rd
        path: /var/lib/ssl/ta.jks
```

##### Disable Upload Certificate Check

Because of an error in DGC Gateway the uploader certificate check can fail. Therefore property to disable the uploader
certificate check was introduced:

```yml
dgc:
  gateway:
    connector:
      disable-upload-certificate-check: false
```

This is just a workaround. This "feature" will be removed in future releases.

#### Trusted Certificate Upload

It is also possible to upload new trusted certificates to provide them to other member states. Therefore the
```DgcGatewayUploadConnector``` needs to be injected. Certificates can then be send to the gateway by calling the
```uploadTrustedCertificate``` with the certificate to upload as parameter. The signing with upload certificate is
handled by the connector.

The following properties needs to be set in order to upload trusted certificates.

 ```yml
dgc:
  gateway:
    connector:
      enabled: true
      endpoint: https://dgcg.example.org
      proxy:
        enabled: false
        host:
        port: -1
      max-cache-age: 300
      tls-trust-store:
        password: dgcg-p4ssw0rd
        path: classpath:tls-truststore.jks
      tls-key-store:
        alias: mtls_private_cert
        password: dgcg-p4ssw0rd
        path: /var/lib/ssl/mtls.jks
      upload-key-store:
        alias: upload
        password: dgcg-p4ssw0rd
        path: classpath:upload.p12
```

Certificates can also be deleted from gateway. The method call is equal to uploading new certificates. Just use
```deleteTrustedCertificate``` instead of ```uploadTrustedCertificate```.

### Signing

#### Create Signed Certificate CMS Message

To upload a certificate as trusted issuer it needs to be send as a signed CMS message. The CMS message needs to be
signed by your previously sent signing certificate.

In order to create such a signed message you need you signing certificate and the corresponding private key. You also
need the certificate you want to envelope into the signed message. Both certificates should be in BouncyCastle's
X509CertificateHolder format

To create the signed message the following call is required:

```java
String signedMessaged=new SignedCertificateMessageBuilder()
    .withSigningCertificate(signingCert,signingCertPrivateKey)
    .withPayloadCertificate(inputCert)
    .buildAsString();
```

This call returns a base64 encoded string with the signed message.

If one of your certificates is in X509Certificate format you can simply convert them using the convert methods from
Utils package.

##### Detached Message

It is also possible to create a detached signature. Just pass the boolean value ```true``` to the ```build()```
or ```buildAsString()``` method.

```java
String detachedSignature=new SignedCertificateMessageBuilder()
    .withSigningCertificate(signingCert,signingCertPrivateKey)
    .withPayloadCertificate(inputCert)
    .buildAsString(true);
```

#### Parse Signed Certificate CMS Message

When a certificate is received it needs to be "unpacked". To do so the SignedCertificateMessageParser can be utilized.

Simply instantiate ```SignedCertificateMessageParser``` with the base64 encoded String.

```java
SignedCertificateMessageParser parser=new SignedCertificateMessageParser(inputString);
```

The constructor accepts different formats as incoming message. Also detached signatures are accepted.

```java
SignedCertificateMessageParser parser=new SignedCertificateMessageParser(payloadByteArray,signatureString);
```

All combinations of String and byte[] as parameter for signature and payload are possible. Please be aware that the
payload will be always base64 encoded (even if it is passed as byte[]).

The parser will immediately parse the message. The result can be obtained from

```java
parser.getParserState()
```

If the state is ```SUCCESS``` the syntax of the message was correct and the certificate could be parsed.

Also the parser checks if the signature of the CMS message was created by the embedded signer certificate. To obtain the
result of this check just read the property

```java
parser.isSignatureVerified()
```

The signer certificate and the containing certificate can be accessed by

```java
parser.getSigningCertificate()
    parser.getPayloadCertificate()
```

Also a detached signature can be gained from parsed message

```java
parser.getSignature()
```

### Utils

### Certificate Utils

The Certificate Utils class provides a few methods related to certificate handling. The class can be injected through
Spring's Dependency Injection.

#### Convert Certificate

The convert Certificate can be used to convert a X509Certificate into BouncyCastle's X509CertificateHolder format and
vice versa.

```java
import eu.europa.ec.dgc.utils.CertificateUtils;
import org.springframework.beans.factory.annotation.Autowired;

class Convert {

    @Autowired
    CertificateUtils certificateUtils;

    public static void main() {
        X509Certificate x509Certificate = cert; /* your X509Certificate */
        X509CertificateHolder x509CertificateHolder = certificateUtils.convertCertificate(x509Certificate);
    }
}
```

#### Calculate Certificate SHA-256 Hash

This method can be used to calculate the SHA-256 hash of X509Certificate (or BouncyCastle's X509CertificateHolder)
The result is a String encoded Hex String containing the certificates hash (64 character)

```java
import eu.europa.ec.dgc.utils.CertificateUtils;
import org.springframework.beans.factory.annotation.Autowired;

class Hash {

    @Autowired
    CertificateUtils certificateUtils;

    public static void main() {
        System.out.println(
            certificateUtils.getCertThumbprint(x509Certificate)
        );
    }
}
```

#### Calculate Certificate KID

This method can be used to calculate the KID of X509Certificate (or BouncyCastle's X509CertificateHolder)
The format of this KID is used in Digital Green Certificate Context.

```java
import eu.europa.ec.dgc.utils.CertificateUtils;
import org.springframework.beans.factory.annotation.Autowired;

class KidTest {

    @Autowired
    CertificateUtils certificateUtils;

    public static void main() {
        System.out.println(
            certificateUtils.getCertKid(x509Certificate)
        );
    }
}
```

## Support and feedback

The following channels are available for discussions, feedback, and support requests:

| Type                      | Channel                                                |
| ------------------------- | ------------------------------------------------------ |
| **DGC Gateway
issues**    | <a href="https://github.com/eu-digital-green-certificates/dgc-gateway/issues" title="Open Issues"><img src="https://img.shields.io/github/issues/eu-digital-green-certificates/dgc-gateway?style=flat"></a>  |
| **DGC Lib
issues**        | <a href="/../../issues" title="Open Issues"><img src="https://img.shields.io/github/issues/eu-digital-green-certificates/dgc-lib?style=flat"></a>  |
| **Other
requests**        | <a href="mailto:opensource@telekom.de" title="Email DGC Team"><img src="https://img.shields.io/badge/email-DGC%20team-green?logo=mail.ru&style=flat-square&logoColor=white"></a>   |

## How to contribute

Contribution and feedback is encouraged and always welcome. For more information about how to contribute, the project
structure, as well as additional contribution information, see our [Contribution Guidelines](./CONTRIBUTING.md). By
participating in this project, you agree to abide by its [Code of Conduct](./CODE_OF_CONDUCT.md) at all times.

## Contributors

Our commitment to open source means that we are enabling -in fact encouraging- all interested parties to contribute and
become part of its developer community.

## Licensing

Copyright (C) 2021 T-Systems International GmbH and all other contributors

Licensed under the **Apache License, Version 2.0** (the "License"); you may not use this file except in compliance with
the License.

You may obtain a copy of the License at https://www.apache.org/licenses/LICENSE-2.0.

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "
AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the [LICENSE](./LICENSE) for
the specific language governing permissions and limitations under the License.
