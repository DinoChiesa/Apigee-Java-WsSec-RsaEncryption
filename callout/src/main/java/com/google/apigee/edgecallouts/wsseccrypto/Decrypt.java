// Copyright 2018-2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package com.google.apigee.edgecallouts.wsseccrypto;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.google.apigee.xml.Namespaces;
import java.io.IOException;
import java.io.StringReader;
import java.security.Key;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;
import javax.naming.InvalidNameException;
import javax.xml.crypto.dsig.XMLSignature;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public class Decrypt extends WssecCalloutBase implements Execution {
  private static final int PEM_LINE_LENGTH = 64;

  public Decrypt(Map properties) {
    super(properties);
  }

  private static Element getSecurityElement(Document doc, String soapNs) {
    NodeList nl = doc.getElementsByTagNameNS(soapNs, "Envelope");
    if (nl.getLength() != 1) {
      throw new RuntimeException("No element: soap:Envelope");
    }
    Element envelope = (Element) nl.item(0);
    nl = envelope.getElementsByTagNameNS(soapNs, "Header");
    if (nl.getLength() != 1) {
      throw new RuntimeException("No element: soap:Header");
    }
    Element header = (Element) nl.item(0);
    nl = header.getElementsByTagNameNS(Namespaces.WSSEC, "Security");
    if (nl.getLength() != 1) {
      throw new RuntimeException("No element: wssec:Security");
    }
    return (Element) nl.item(0);
  }

  private static String toCertPEM(String s) {
    int len = s.length();
    int sIndex = 0;
    int eIndex = PEM_LINE_LENGTH;
    StringBuilder sb = new StringBuilder();
    sb.append("-----BEGIN CERTIFICATE-----\n");
    while (sIndex < len) {
      sb.append(s.substring(sIndex, eIndex));
      sb.append("\n");
      sIndex += PEM_LINE_LENGTH;
      eIndex += PEM_LINE_LENGTH;
      if (eIndex > len) {
        eIndex = len;
      }
    }
    sb.append("-----END CERTIFICATE-----\n");
    s = sb.toString();
    return s;
  }

  private static Element getNamedElementWithId(
      String xmlns, String soapNs, String tagName, String id, Document doc) {
    id = id.substring(1); // chopLeft
    NodeList nl = getSecurityElement(doc, soapNs).getElementsByTagNameNS(xmlns, tagName);
    for (int i = 0; i < nl.getLength(); i++) {
      Element candidate = (Element) nl.item(i);
      String candidateId = candidate.getAttributeNS(Namespaces.WSU, "Id");
      if (id.equals(candidateId)) return candidate;
    }
    return null;
  }

  private Certificate getCertificate(
      Element keyInfo, Document doc, String soapNs, MessageContext msgCtxt)
      throws KeyException, NoSuchAlgorithmException, InvalidNameException,
          CertificateEncodingException {
    // There are 4 cases to handle:
    // 1. SecurityTokenReference pointing to a BinarySecurityToken
    // 2. SecurityTokenReference with a thumbprint
    // 3. SecurityTokenReference with IssuerName and SerialNumber
    // 4. X509Data with Raw cert data
    //
    // In cases 1 and 4, we have the cert in the document.
    // In cases 2 and 3, the verifier must provide the cert separately, and the validity
    // check must verify that the thumbprint or IssuerName and SerialNumber match.

    // There is a 5th case,
    // 5. KeyValue with RSAKeyValue and Modulus + Exponent
    //
    // In case 5, ... we have the public key in the document. Not a cert.
    // this code does not handle verification for that kind of signature.
    //

    NodeList nl = keyInfo.getElementsByTagNameNS(Namespaces.WSSEC, "SecurityTokenReference");
    if (nl.getLength() == 0) {
      nl = keyInfo.getElementsByTagNameNS(XMLSignature.XMLNS, "X509Data");
      if (nl.getLength() == 0) throw new RuntimeException("No suitable child element of KeyInfo");
      Element x509Data = (Element) (nl.item(0));
      nl = x509Data.getElementsByTagNameNS(XMLSignature.XMLNS, "X509Certificate");
      if (nl.getLength() == 0)
        throw new RuntimeException("No X509Certificate child element of KeyInfo/X509Data");

      // case 4: X509Data with raw data
      Element x509Cert = (Element) (nl.item(0));

      String base64String = x509Cert.getTextContent();
      Certificate cert = certificateFromPEM(toCertPEM(base64String));
      return cert;
    }

    Element str = (Element) nl.item(0);
    nl = str.getElementsByTagNameNS(Namespaces.WSSEC, "Reference");
    // nl = keyInfo.getChildNodes();
    // Element reference = (Element) nl.item(0);
    if (nl.getLength() == 0) {
      nl = str.getElementsByTagNameNS(Namespaces.WSSEC, "KeyIdentifier");
      if (nl.getLength() == 0) {
        nl = str.getElementsByTagNameNS(XMLSignature.XMLNS, "X509Data");
        if (nl.getLength() == 0)
          throw new RuntimeException(
              "No suitable child element beneath: KeyInfo/SecurityTokenReference");

        // case 3: SecurityTokenReference with IssuerName and SerialNumber
        Element x509Data = (Element) (nl.item(0));
        nl = x509Data.getElementsByTagNameNS(XMLSignature.XMLNS, "X509IssuerSerial");
        if (nl.getLength() == 0)
          throw new RuntimeException(
              "No X509IssuerSerial child element of KeyInfo/SecurityTokenReference/X509Data");
        Element x509IssuerSerial = (Element) (nl.item(0));
        nl = x509IssuerSerial.getElementsByTagNameNS(XMLSignature.XMLNS, "X509IssuerName");
        if (nl.getLength() == 0) throw new RuntimeException("No X509IssuerName element found");
        Element x509IssuerName = (Element) (nl.item(0));

        nl = x509IssuerSerial.getElementsByTagNameNS(XMLSignature.XMLNS, "X509SerialNumber");
        if (nl.getLength() == 0) throw new RuntimeException("No X509IssuerName element found");
        Element x509SerialNumber = (Element) (nl.item(0));
        X509Certificate cert = getCertificate(msgCtxt);

        // check that the serial number matches
        String assertedSerialNumber = x509SerialNumber.getTextContent();
        if (assertedSerialNumber == null)
          throw new RuntimeException("KeyInfo/SecurityTokenReference/../X509SerialNumber missing");
        String availableSerialNumber = cert.getSerialNumber().toString();
        if (!assertedSerialNumber.equals(availableSerialNumber))
          throw new RuntimeException(
              String.format(
                  "X509SerialNumber mismatch cert(%s) doc(%s)",
                  availableSerialNumber, assertedSerialNumber));

        // check that the issuer name matches
        String assertedIssuerName = x509IssuerName.getTextContent();
        if (assertedIssuerName == null)
          throw new RuntimeException("KeyInfo/SecurityTokenReference/../X509IssuerName missing");
        IssuerNameStyle nameStyle = getIssuerNameStyle(msgCtxt);

        String availableIssuerName =
            (nameStyle == IssuerNameStyle.SHORT)
                ? "CN=" + getCommonName(cert.getSubjectX500Principal())
                : cert.getSubjectDN().getName();

        if (!assertedIssuerName.equals(availableIssuerName))
          throw new RuntimeException(
              String.format(
                  "X509SerialNumber mismatch cert(%s) doc(%s)",
                  availableIssuerName, assertedIssuerName));

        return cert;
      }

      // case 2: KeyIdentifier with thumbprint
      Element ki = (Element) nl.item(0);
      String valueType = ki.getAttribute("ValueType");
      if (valueType == null
          || !valueType.equals(
              "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security1.1#ThumbprintSHA1"))
        throw new RuntimeException(
            "KeyInfo/SecurityTokenReference/KeyIdentifier unsupported ValueType");

      String assertedThumbprintSha1Base64 = ki.getTextContent();
      if (assertedThumbprintSha1Base64 == null)
        throw new RuntimeException("KeyInfo/SecurityTokenReference/KeyIdentifier no thumbprint");

      X509Certificate cert = getCertificate(msgCtxt);
      String availableThumbprintSha1Base64 = getThumbprintBase64(cert);
      if (!assertedThumbprintSha1Base64.equals(availableThumbprintSha1Base64))
        throw new RuntimeException(
            "KeyInfo/SecurityTokenReference/KeyIdentifier thumbprint mismatch");
      return cert;
    }

    // case 1: SecurityTokenReference pointing to a BinarySecurityToken
    Element reference = (Element) nl.item(0);
    String strUri = reference.getAttribute("URI");
    if (strUri == null || !strUri.startsWith("#")) {
      throw new RuntimeException(
          "Unsupported URI format: KeyInfo/SecurityTokenReference/Reference");
    }
    Element bst =
        getNamedElementWithId(Namespaces.WSSEC, soapNs, "BinarySecurityToken", strUri, doc);
    if (bst == null) {
      throw new RuntimeException("Unresolvable reference: #" + strUri);
    }
    String bstNs = bst.getNamespaceURI();
    String tagName = bst.getLocalName();
    if (bstNs == null
        || !bstNs.equals(Namespaces.WSSEC)
        || tagName == null
        || !tagName.equals("BinarySecurityToken")) {
      throw new RuntimeException("Unsupported SecurityTokenReference type");
    }
    String encodingType = bst.getAttribute("EncodingType");
    if (encodingType == null
        || !encodingType.equals(
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary")) {
      throw new RuntimeException("Unsupported SecurityTokenReference EncodingType");
    }
    String valueType = bst.getAttribute("ValueType");
    if (valueType == null
        || !valueType.equals(
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3")) {
      throw new RuntimeException("Unsupported SecurityTokenReference ValueType");
    }
    String base64String = bst.getTextContent();
    Certificate cert = certificateFromPEM(toCertPEM(base64String));
    return cert;
  }

  private static class DocumentEncryptionState {
    public String soapns;
    public String contentEncryptionAlgorithm;
    public Element encryptedKeyElement;
    public Element encryptedDataElement;
  }

  private static DocumentEncryptionState checkCompulsoryElements(Document doc, DecryptConfiguration configuration) {
    NodeList nl = null;
    DocumentEncryptionState state = new DocumentEncryptionState();
    state.soapns =
        (configuration.soapVersion.equals("soap1.2")) ? Namespaces.SOAP1_2 : Namespaces.SOAP1_1;

    nl = doc.getElementsByTagNameNS(state.soapns, "Envelope");
    if (nl.getLength() == 0) throw new IllegalStateException("no Envelope");
    if (nl.getLength() != 1) throw new IllegalStateException("more than one Envelope");

    Element envelope = (Element) nl.item(0);

    nl = envelope.getElementsByTagNameNS(state.soapns, "Header");
    if (nl.getLength() == 0) throw new IllegalStateException("no Header");
    if (nl.getLength() != 1) throw new IllegalStateException("more than one Header");
    Element header = (Element) nl.item(0);

    nl = header.getElementsByTagNameNS(Namespaces.WSSEC, "Security");
    if (nl.getLength() == 0) throw new IllegalStateException("no Security");
    if (nl.getLength() != 1) throw new IllegalStateException("more than one Security");
    Element security = (Element) nl.item(0);

    nl = envelope.getElementsByTagNameNS(state.soapns, "Body");
    if (nl.getLength() == 0) throw new IllegalStateException("no Body");
    if (nl.getLength() != 1) throw new IllegalStateException("more than one Body");
    Element body = (Element) nl.item(0);

    nl = body.getElementsByTagNameNS(Namespaces.XMLENC, "EncryptedData");
    if (nl.getLength() == 0) throw new IllegalStateException("no EncryptedData");
    if (nl.getLength() != 1) throw new IllegalStateException("more than one EncryptedData");
    Element encryptedData = (Element) nl.item(0);
    state.encryptedDataElement = encryptedData;

    nl = encryptedData.getElementsByTagNameNS(Namespaces.XMLENC, "EncryptedKey");
    if (nl.getLength() == 0) {
      // EncryptedKey may be a child of wssec:Security
      nl = security.getElementsByTagNameNS(Namespaces.XMLENC, "EncryptedKey");
      if (nl.getLength() == 0)
        throw new IllegalStateException("no EncryptedKey");
    }

    if (nl.getLength() != 1)
      throw new IllegalStateException("more than one EncryptedKey");

    Element encryptedKey = (Element) nl.item(0);
    state.encryptedKeyElement = encryptedKey;

    nl = encryptedKey.getElementsByTagNameNS(Namespaces.XMLENC, "EncryptionMethod");
    if (nl.getLength() == 0)
      throw new IllegalStateException("no EncryptedKey/EncryptionMethod");
    if (nl.getLength() != 1)
      throw new IllegalStateException("more than one EncryptedKey/EncryptionMethod");
    Element encryptionMethod = (Element) nl.item(0);
    String methodAlgorithm = encryptionMethod.getAttribute("Algorithm");

    if (!methodAlgorithm.equals("http://www.w3.org/2001/04/xmlenc#rsa-1_5") &&
        !methodAlgorithm.equals("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"))
      throw new IllegalStateException("unsupported EncryptionMethod for EncryptedKey");

    encryptionMethod = getChildElementsByTagNameNS(encryptedData, Namespaces.XMLENC, "EncryptionMethod");

    if (encryptionMethod == null)
      throw new IllegalStateException("no EncryptedData/EncryptionMethod");

    state.contentEncryptionAlgorithm = encryptionMethod.getAttribute("Algorithm");

    return state;
  }

  private Document decrypt_RSA(Document doc, DecryptConfiguration configuration) throws Exception {
    DocumentEncryptionState state = checkCompulsoryElements(doc, configuration);
    if (configuration.contentEncryptionCipher != ContentEncryptionCipher.NONE) {
      if (!state.contentEncryptionAlgorithm.equals(
          configuration.contentEncryptionCipher.asXmlCipherString()))
        throw new IllegalStateException("unacceptable Content EncryptionMethod");
    }

    // this works regardless where the EncryptedKey is found
    XMLCipher xmlCipher = XMLCipher.getInstance();
    xmlCipher.init(XMLCipher.DECRYPT_MODE, null);
    EncryptedData encryptedData = xmlCipher.loadEncryptedData(doc, state.encryptedDataElement);
    EncryptedKey encryptedKey = xmlCipher.loadEncryptedKey(doc, state.encryptedKeyElement);

    if (encryptedData == null || encryptedKey == null)
      throw new IllegalStateException("Not a valid encrypted document");

    String encAlgoURL = encryptedData.getEncryptionMethod().getAlgorithm();
    XMLCipher keyCipher = XMLCipher.getInstance();
    keyCipher.init(XMLCipher.UNWRAP_MODE, configuration.privateKey);
    Key encryptionKey = keyCipher.decryptKey(encryptedKey, encAlgoURL);
    xmlCipher = XMLCipher.getInstance();
    xmlCipher.init(XMLCipher.DECRYPT_MODE, encryptionKey);

    xmlCipher.doFinal(doc, state.encryptedDataElement, false); // ??
    return doc;
  }

  private static RSAPrivateKey readKey(String privateKeyPemString, String password)
      throws IOException, OperatorCreationException, PKCSException, InvalidKeySpecException,
          NoSuchAlgorithmException {
    if (privateKeyPemString == null) {
      throw new IllegalStateException("PEM String is null");
    }
    if (password == null) password = "";

    PEMParser pr = null;
    try {
      pr = new PEMParser(new StringReader(privateKeyPemString));
      Object o = pr.readObject();

      if (o == null) {
        throw new IllegalStateException("Parsed object is null.  Bad input.");
      }
      if (!((o instanceof PEMEncryptedKeyPair)
          || (o instanceof PKCS8EncryptedPrivateKeyInfo)
          || (o instanceof PrivateKeyInfo)
          || (o instanceof PEMKeyPair))) {
        throw new IllegalStateException(
            "Didn't find OpenSSL key. Found: " + o.getClass().getName());
      }

      JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

      if (o instanceof PEMKeyPair) {
        // eg, "openssl genrsa -out keypair-rsa-2048-unencrypted.pem 2048"
        return (RSAPrivateKey) converter.getPrivateKey(((PEMKeyPair) o).getPrivateKeyInfo());
      }

      if (o instanceof PrivateKeyInfo) {
        // eg, "openssl genpkey  -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -out keypair.pem"
        return (RSAPrivateKey) converter.getPrivateKey((PrivateKeyInfo) o);
      }

      if (o instanceof PKCS8EncryptedPrivateKeyInfo) {
        // eg, "openssl genpkey -algorithm rsa -aes-128-cbc -pkeyopt rsa_keygen_bits:2048 -out
        // private-encrypted.pem"
        PKCS8EncryptedPrivateKeyInfo pkcs8EncryptedPrivateKeyInfo =
            (PKCS8EncryptedPrivateKeyInfo) o;
        JceOpenSSLPKCS8DecryptorProviderBuilder decryptorProviderBuilder =
            new JceOpenSSLPKCS8DecryptorProviderBuilder();
        InputDecryptorProvider decryptorProvider =
            decryptorProviderBuilder.build(password.toCharArray());
        PrivateKeyInfo privateKeyInfo =
            pkcs8EncryptedPrivateKeyInfo.decryptPrivateKeyInfo(decryptorProvider);
        return (RSAPrivateKey) converter.getPrivateKey(privateKeyInfo);
      }

      if (o instanceof PEMEncryptedKeyPair) {
        // eg, "openssl genrsa -aes256 -out private-encrypted-aes-256-cbc.pem 2048"
        PEMDecryptorProvider decProv =
            new JcePEMDecryptorProviderBuilder().setProvider("BC").build(password.toCharArray());
        KeyPair keyPair = converter.getKeyPair(((PEMEncryptedKeyPair) o).decryptKeyPair(decProv));
        return (RSAPrivateKey) keyPair.getPrivate();
      }
    } finally {
      if (pr != null) {
        pr.close();
      }
    }
    throw new IllegalStateException("unknown PEM object");
  }

  private RSAPrivateKey getPrivateKey(MessageContext msgCtxt) throws Exception {
    String privateKeyPemString = getSimpleRequiredProperty("private-key", msgCtxt);
    privateKeyPemString = privateKeyPemString.trim();

    // clear any leading whitespace on each line
    privateKeyPemString = reformIndents(privateKeyPemString);
    String privateKeyPassword = getSimpleOptionalProperty("private-key-password", msgCtxt);
    if (privateKeyPassword == null) privateKeyPassword = "";
    return readKey(privateKeyPemString, privateKeyPassword);
  }

  static class DecryptConfiguration {
    public String soapVersion = Namespaces.SOAP1_1; // default
    public RSAPrivateKey privateKey; // required
    public X509Certificate certificate; // required
    public ContentEncryptionCipher contentEncryptionCipher =
        ContentEncryptionCipher.NONE; // optional

    public DecryptConfiguration() {}

    public DecryptConfiguration withSoapVersion(String version) {
      this.soapVersion = version;
      return this;
    }

    public DecryptConfiguration withPrivateKey(RSAPrivateKey privateKey) {
      this.privateKey = privateKey;
      return this;
    }

    public DecryptConfiguration withContentEncryptionCipher(ContentEncryptionCipher cipher) {
      this.contentEncryptionCipher = cipher;
      return this;
    }
  }

  public ExecutionResult execute(final MessageContext msgCtxt, final ExecutionContext execContext) {
    try {
      msgCtxt.setVariable(varName("valid"), false);
      Document document = getDocument(msgCtxt);

      DecryptConfiguration decryptConfiguration =
          new DecryptConfiguration()
              .withSoapVersion(getSoapVersion(msgCtxt))
              .withPrivateKey(getPrivateKey(msgCtxt))
              // .withAcceptableThumbprints(getAcceptableThumbprints(msgCtxt))
              // .withAcceptableSubjectCNs(getAcceptableSubjectCNs(msgCtxt))
              .withContentEncryptionCipher(getContentEncryptionCipher(msgCtxt));

      Document decryptedDoc = decrypt_RSA(document, decryptConfiguration);

      msgCtxt.setVariable(varName("output"), documentToString(decryptedDoc));
      return ExecutionResult.SUCCESS;

    } catch (IllegalStateException exc1) {
      setExceptionVariables(exc1, msgCtxt);
      return ExecutionResult.ABORT;
    } catch (Exception e) {
      if (getDebug()) {
        String stacktrace = getStackTraceAsString(e);
        msgCtxt.setVariable(varName("stacktrace"), stacktrace);
      }
      setExceptionVariables(e, msgCtxt);
      return ExecutionResult.ABORT;
    }
  }
}
