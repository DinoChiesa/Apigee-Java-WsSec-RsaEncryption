# Java Callout for WS-Security RSA Encryption

This directory contains the Java source code and pom.xml file required to
compile a simple Java callout for Apigee Edge, that encrypts or decrypts the
Body of a SOAP message per the WS-Security standard, using an RSA Key and an
x509v3 certificate.


## Disclaimer

This example is not an official Google product, nor is it part of an official Google product.

## License

This material is Copyright 2018-2020, Google LLC.
and is licensed under the Apache 2.0 license. See the [LICENSE](LICENSE) file.

This code is open source but you don't need to compile it in order to use it.

## Building

Use maven to build and package the jar. You need maven v3.5 at a minimum.

```
mvn clean package
```

The 'package' goal will copy the jar to the resources/java directory for the
example proxy bundle. If you want to use this in your own API Proxy, you need
to drop this JAR into the appropriate API Proxy bundle. Or include the jar as an
environment-wide or organization-wide jar via the Apigee administrative API.


## Details

There is a single jar, apigee-wssec-xmlenc-20200413.jar . Within that jar, there are two callout classes,

* com.google.apigee.edgecallouts.wsseccrypto.Encrypt - encrypts a SOAP document.
* com.google.apigee.edgecallouts.wsseccrypto.Decrypt - decrypts the encrypted SOAP document

The Encrypt callout has these constraints and features:
* supports RSA key encryption algorithms - PKCS1.5 or OAEP
* supports AES content encryption algorithms - AES 128, 192, 256, in CBC or GCM
* supports soap1.1 and soap1.2
* encrypts the SOAP Body
* has options for embedding the Key and the certificate in the encrypted document

The Decrypt callout has these constraints and features:
* supports RSA algorithms - PKCS1.5 and OAEP
* supports AES content encryption algorithms - AES 128, 192, 256, in CBC or GCM
* supports soap1.1. (Not tested with soap 1.2; might work!)

## Dependencies

Make sure these JARs are available as resources in the  proxy or in the environment or organization.

* xmlsec-2.1.5.jar and its dependencies

## Usage

### Encryption

A simple policy that accepts an inbound SOAP document and encrypts the body
looks like this:

```xml
<JavaCallout name='Java-WSSEC-Encrypt-1'>
  <Properties>
    <Property name='source'>message.content</Property>
    <Property name='output-variable'>output</Property>
    <Property name='certificate'>{my_certificate}</Property>
  </Properties>
  <ClassName>com.google.apigee.edgecallouts.wsseccrypto.Encrypt</ClassName>
  <ResourceURL>java://apigee-wssec-xmlenc-20200413.jar</ResourceURL>
</JavaCallout>
```

What this says:
* accept a SOAP document from message.content
* use the certificate specified (in PEM format) to extract an RSA Public Key for
  the encryption
* use the defaults for RSA algorithm, and key location, and certificate
  embedding
* place the output into the context variable `output`


For a source document like this:
```xml
<soapenv:Envelope
    xmlns:ns1='http://ws.example.com/'
    xmlns:soapenv='http://schemas.xmlsoap.org/soap/envelope/'>
  <soapenv:Body>
    <ns1:sumResponse>
      <ns1:return>9</ns1:return>
    </ns1:sumResponse>
  </soapenv:Body>
</soapenv:Envelope>
```

The result is a document like this:
```xml
<soapenv:Envelope
    xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:wssec="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
    xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
    xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"
    xmlns:ns1="http://ws.example.com/"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <soapenv:Header>
    <wssec:Security soapenv:mustUnderstand="1">
      <wssec:BinarySecurityToken EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" wsu:Id="SecurityToken-98d649fe-4941-468c-a24d-c1c57ef19d34">MIIDpDCCAowCCQDsXkZg2rbAwTANBgkqhkiG9w0BAQUFADCBkzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xETAPBgNVBAcMCEtpcmtsYW5kMQ8wDQYDVQQKDAZHb29nbGUxDzANBgNVBAsMBkFwaWdlZTEaMBgGA1UEAwwRYXBpZ2VlLmdvb2dsZS5jb20xHjAcBgkqhkiG9w0BCQEWD2Rpbm9AYXBpZ2VlLmNvbTAeFw0xOTEwMDgxMTExMjBaFw0yOTEwMDUxMTExMjBaMIGTMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjERMA8GA1UEBwwIS2lya2xhbmQxDzANBgNVBAoMBkdvb2dsZTEPMA0GA1UECwwGQXBpZ2VlMRowGAYDVQQDDBFhcGlnZWUuZ29vZ2xlLmNvbTEeMBwGCSqGSIb3DQEJARYPZGlub0BhcGlnZWUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqJA2NwXeqXaVaHO0mkKDpTdhPCh/80gH2Oun4DJOYjYgvdMRJ83xB6Hwm809T593rkX9PwOjUDQ7kJvH0aLaqxb+FrrTDTFcXZXJZ65dca9lYARxgEAwasPIkvBdr0nP2W2VQgPKtkwStZinMiJh/JSlXCz7ULDGVqW8FyklGaVIkxrXhHsjH+hhJ8Kp+zjFsfdsTkGbaqXj/qexeHUBcF6GbHe7xhaLoj/P24D7mFHB3uXx4vN3ohP+ZiT1y5X8fCLVu5SSC+vDFHR2Z5I26yTlcNRwKt24lNypGsEzM5KZILJlEr3BnAA1qkcSX7wZQDHp3XOHJHaR6lxarvYlmQIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQBD+S4bF8b07955E7HshWFez5Q4/7cXhGPjFaiNw9lH9Ny1iIcblRl36iiVda4Lemy1Kxa5xGJ+I5NZ8k1MyxZ1x5K9bPX5LiI8ThLGRxBNUNLgaoQ+7FZLklpZARoIuQ3Gg90V0qUqkm2eipgZxzdtEGj+lqoX10A2B+wimO6nzUv6vYoJARMBtqsYmQKz5GRBoajGdMn60UF9Ry5B32k31JVpat4qm7+Ig1YMwv2nfY6bgHzsI4WjETOLvFCYgBDJzIEy+0jA1FUe5Ec5Fs5nmiG8F7FRJ/9aYb1e+cbQVRZyc1wKlmIReK/LgG8FjdDjeqFZTg0AjInG8/oOz5ib</wssec:BinarySecurityToken>
      <xenc:EncryptedKey>
        <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/>
        <ds:KeyInfo>
          <wssec:SecurityTokenReference>
            <wssec:Reference URI="#SecurityToken-98d649fe-4941-468c-a24d-c1c57ef19d34" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"/>
          </wssec:SecurityTokenReference>
        </ds:KeyInfo>
        <xenc:CipherData>
          <xenc:CipherValue>K1U0yu1I7/EY2SSzKphZAQ+JX4Du9eDK0fPmNorkOtQfV+hpGpiHyq10ykN88Y9uneFvvwkM8mAx&#xD;
          9FT7f/AvWRE3SLCgVPu8UNK12byWZPGVm3oHjOopo9nD3jjFrT33qgyy4dwAeXekdfhrRO5edfl5&#xD;
          jkIC1iFAfmjmKHKEKpjPsM3Ba/sB89mS0MUQxuyZzo42TxcFcw0nvnc8rR6iy4AOMDkBz0wzHH7U&#xD;
          0M3FIfVK9JOkGUxZGK+ztATM0HwAmhUw362rq1or9Z4OqHE3e1p9B+AHh4tV+D0DbAG9sF0x3SBK&#xD;
          XIa63vOkN5co8sQ0s9b2tTpS6k0foNkZvIJ88Q==</xenc:CipherValue>
        </xenc:CipherData>
        <xenc:ReferenceList>
          <xenc:DataReference URI="#Enc-1"/>
        </xenc:ReferenceList>
      </xenc:EncryptedKey>
    </wssec:Security>
  </soapenv:Header>
  <soapenv:Body wsu:Id="Body-a5a5ab07-26fe-404c-a8e3-f353f6cb2831">
    <xenc:EncryptedData Id="Enc-1" Type="http://www.w3.org/2001/04/xmlenc#Element">
      <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes192-cbc"/>
      <xenc:CipherData>
        <xenc:CipherValue>HJ6LzvAYym73A5A3llk3UPQft8Dk5IYH1bVJngj0xbJexo3MfWX0/f2ee4Kdxz42+6YysDCgpXwl&#xD;
        7irG4WdM4yqpVwqBeeWg9G9sVmfnfnOTvHPQRBPb4CFVpSuQk0y9</xenc:CipherValue>
      </xenc:CipherData>
    </xenc:EncryptedData>
  </soapenv:Body>
</soapenv:Envelope>
```


You can see that:
* the `soap:Body` element is now replaced with `xenc:EncryptedData`
* There is an `EncryptedKey` element placed in the `soap:Header`. This is the symmetric
  content-encryption key
* The x509 certificate used is embedded in a `wsse:BinarySecurityToken` in the `soap:Header`.
* The content-encryption algorithm is aes192-cbc (the default)
* The key-encryption algorithm is RSA PKCS1.5 (the default)

By changing the properties applied to the policy,  there are numerous other
variations possible.

The available properties are:

| name                   | description                                                   |
| ---------------------- | ------------------------------------------------------------- |
| source                 | source of the SOAP document to sign. Usually message.content. |
| soap-version           | soap1.1 or soap1.2.  Defaults to soap1.1                      |
| certificate            | required. the X509v3 certificate to use for the public key for encryption. This cert will then be referenced in the encrypted document in some way. |
| rsa-algorithm          | optional. PKCS1\_5 or OAEP. Defaults to PKCS1\_5                        |
| key-identifier-type    | optional. how to embed a reference to the key in the output document.   |
| encrypted-key-location | optional. where to embed the encrypted key in the output document.  This is either `in-security-header` or `under-encrypted-data`, Defaults to in header.  |
| issuer-name-style      | optional. One of {`SHORT`, `SUBJECT_DN`}.  See below for details. |
| content-encryption-cipher | AES-128-CBC, AES-192-CBC, AES-256-CBC, AES-128-GCM, AES-192-GCM, AES-256-GCM or TRIPLEDES. Defaults to AES-128-CBC. ) |


Regarding `key-identifier-type`, these are the options:

* `bst_direct_reference`. This is the default; this is what you get if you omit
  this property. With this setting, the Sign callout embeds the certificate into
  the signed document using a BinarySecurityToken and a SecurityTokenReference
  that points to it.

  The KeyInfo element looks like this:
  ```xml
   <KeyInfo>
     <wssec:SecurityTokenReference>
       <wssec:Reference URI="#SecurityToken-e828bfab-bb52-4429"
           ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"/>
     </wssec:SecurityTokenReference>
   </KeyInfo>
  ```

  And there will be a child element of the wssec:Security element that looks like
  this:
  ```xml
      <wssec:BinarySecurityToken
          EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
          ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
          wsu:Id="SecurityToken-e828bfab-bb52-4429-b6a4-755b26abc387">MIIC0...</wssec:BinarySecurityToken>
  ```

* `thumbprint` gives you this:

  ```xml
   <KeyInfo>
     <wsse:SecurityTokenReference>
       <wsse:KeyIdentifier
             ValueType="http://docs.oasis-open.org/wss/oasis-wss-soap-message-security1.1#ThumbprintSHA1">9JscCwWHk5IvR/6JLTSayTY7M=</wsse:KeyIdentifier>
     </wsse:SecurityTokenReference>
   </KeyInfo>
  ```

* `issuer_serial` (common with WCF) results in this:

  ```xml
   <KeyInfo>
     <wsse:SecurityTokenReference wsu:Id="STR-2795B41DA34FD80A771574109162615125">
       <X509Data>
         <X509IssuerSerial>
           <X509IssuerName>CN=common.name.on.cert</X509IssuerName>
           <X509SerialNumber>837113432321</X509SerialNumber>
         </X509IssuerSerial>
       </X509Data>
     </wsse:SecurityTokenReference>
   </KeyInfo>
  ```

  For this case, you can specify another property, `issuer-name-style`, as
  either `short` or `subject_dn`.  The former is the default. The latter results
  in something like this:
   ```xml
   <X509IssuerSerial>
     <X509IssuerName>C=US,ST=Washington,L=Kirkland,O=Google,OU=Apigee,CN=apigee.google.com,E=dino@apigee.com</X509IssuerName>
     <X509SerialNumber>837113432321</X509SerialNumber>
   </X509IssuerSerial>
   ```

* `x509_cert_direct` gives you this:
  ```xml
  <KeyInfo>
     <X509Data>
       <X509Certificate>MIICAjCCAWu....7BQnulQ=</X509Certificate>
     </X509Data>
   </KeyInfo>
  ```

* `rsa_key_value` gives you this:
  ```xml
  <KeyInfo>
    <KeyValue>
       <RSAKeyValue>
         <Modulus>B6PenDyT58LjZlG6LYD27IFCh1yO+4...yCP9YNDtsLZftMLoQ==</Modulus>
         <Exponent>AQAB</Exponent>
       </RSAKeyValue>
     </KeyValue>
   </KeyInfo>
  ```


### Decrypting

```xml
<JavaCallout name='Java-WSSEC-Decrypt-1'>
  <Properties>
    <Property name='source'>message.content</Property>
    <Property name='require-expiry'>false</Property>
    <Property name='private-key'>{my_private_key}</Property>
  </Properties>
  <ClassName>com.google.apigee.edgecallouts.wsseccrypto.Decrypt</ClassName>
  <ResourceURL>java://apigee-wssec-xmlenc-20200413.jar</ResourceURL>
</JavaCallout>
```

The properties are:

| name                   | description |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------ |
| source                 | optional. the variable name in which to obtain the source signed document to validate. Defaults to message.content |
| private-key            | required. The PEM file containing the RSA private key to decrypt. |
| rsa-algorithm          | optional. Specify PKCS1\_5 or OAEP to require either of these.   |
| content-encryption-algorithm | optional. Specify one of the AES-* or TRIPLEDES to require tone of those. |

See [the example API proxy included here](./bundle) for a working example of these policy configurations.


## Example API Proxy Bundle

Deploy the API Proxy to an organization and environment using a tool like [importAndDeploy.js](https://github.com/DinoChiesa/apigee-edge-js/blob/master/examples/importAndDeploy.js)

There are some sample SOAP request documents included in this repo that you can use for demonstrations.

### Invoking the Example proxy:

This request encrypts using key encryption RSA PKCS1.5,  content encryption AES-128-CBC,
using BinarySecurityToken to embed the certificate:

```
ORG=myorgname
ENV=myenv
curl -i https://${ORG}-${ENV}.apigee.net/wssec-enc/encrypt1  -H content-type:application/xml \
    --data-binary @./sample-data/request1.xml
```

There are other combinations; see the API Proxy bundle for the variations of
encryption options.

This request decrypts:

   ```
   curl -i https://${ORG}-${ENV}.apigee.net/wssec-enc/decrypt1  -H content-type:application/xml \
       --data-binary @./sample-data/encrypted-request.xml
   ```
The output of the above should indicate that the signature on the document is
valid.


## About Keys

There is a private RSA key and a corresponding certificate embedded in the API
Proxy. You should not use those for your own purposes. Create your
own. Self-signed is fine for testing purposes. You can
do it with openssl. Creating a privatekey, a certificate signing request, and a
certificate, is as easy as 1, 2, 3:

```
 openssl genpkey  -algorithm rsa -pkeyopt  rsa_keygen_bits:2048 -out privatekey.pem
 openssl req -key privatekey.pem -new -out domain.csr
 openssl x509 -req -days 3650 -in domain.csr -signkey privatekey.pem -out domain.cert
```


## Bugs

none?
