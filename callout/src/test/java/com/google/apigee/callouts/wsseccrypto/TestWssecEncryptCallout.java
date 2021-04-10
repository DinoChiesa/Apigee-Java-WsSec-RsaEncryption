package com.google.apigee.callouts.wsseccrypto;

import com.apigee.flow.execution.ExecutionResult;
import com.google.apigee.xml.Namespaces;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class TestWssecEncryptCallout extends CalloutTestBase {

  private static final String RSA_PKCS_1_5 =
    "http://www.w3.org/2001/04/xmlenc#rsa-1_5";

  private static final String RSA_OAEP =
    "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";

  private static final String simpleSoap11 =
      "<soapenv:Envelope xmlns:ns1='http://ws.example.com/' xmlns:soapenv='http://schemas.xmlsoap.org/soap/envelope/'>"
          + "  <soapenv:Body>"
          + "    <ns1:sumResponse>"
          + "      <ns1:return>9</ns1:return>"
          + "    </ns1:sumResponse>"
          + "  </soapenv:Body>"
          + "</soapenv:Envelope>";

  private static final String simpleSoap12 =
      ""
          + "<soap:Envelope \n"
          + "    xmlns:soap='http://www.w3.org/2003/05/soap-envelope'\n"
          + "    xmlns:v1='https://foo/servicecontract/v1.0'\n"
          + "    xmlns:v11='https://foo/claims/datacontract/v1.0'>\n"
          + "  <soap:Header \n"
          + "      xmlns:wsa='http://www.w3.org/2005/08/addressing'>\n"
          + "    <wsa:Action>https://foo/v1.0/ClaimsService/FileMultipleClaims</wsa:Action>\n"
          + "    <wsa:To>https://foo/v1.0/ClaimsService</wsa:To>\n"
          + "  </soap:Header>\n"
          + "  <soap:Body>\n"
          + "    <ns2:FileMultipleClaims \n"
          + "        xmlns:ns2='https://foo/servicecontract/v1.0'\n"
          + "        xmlns='https://foo/claims/datacontract/v1.0'>\n"
          + "      <ns2:request>\n"
          + "        <body>here</body>\n"
          + "      </ns2:request>\n"
          + "    </ns2:FileMultipleClaims>\n"
          + "  </soap:Body>\n"
          + "</soap:Envelope>\n";

  private static Document docFromStream(InputStream inputStream)
      throws IOException, ParserConfigurationException, SAXException {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    Document doc = dbf.newDocumentBuilder().parse(inputStream);
    return doc;
  }

  @Test
  public void emptySource() throws Exception {
    String method = "emptySource() ";
    String expectedError = "source variable resolves to null";
    msgCtxt.setVariable("message-content", simpleSoap11);

    Map<String, String> props = new HashMap<String, String>();
    props.put("source", "not-message.content");

    Encrypt callout = new Encrypt(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNotNull(errorOutput, "errorOutput");
    // System.out.printf("expected error: %s\n", errorOutput);
    Assert.assertEquals(errorOutput, expectedError, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");
  }

  @Test
  public void missingCertificate() throws Exception {
    String method = "missingCertificate() ";
    String expectedError = "certificate resolves to an empty string";

    msgCtxt.setVariable("message.content", simpleSoap11);

    Map<String, String> props = new HashMap<String, String>();
    props.put("source", "message.content");

    Encrypt callout = new Encrypt(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNotNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNotNull(errorOutput, "errorOutput");
    // System.out.printf("expected error: %s\n", errorOutput);
    Assert.assertEquals(errorOutput, expectedError, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");
  }

  @Test
  public void validResult() throws Exception {
    String method = "validResult() ";
    msgCtxt.setVariable("message.content", simpleSoap11);
    // msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    // props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
    props.put("output-variable", "output");

    Encrypt callout = new Encrypt(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");
    verifyOutput(method, output, "http://www.w3.org/2001/04/xmlenc#aes192-cbc",
                 RSA_PKCS_1_5);
  }

  @Test
  public void aes192gcm() throws Exception {
    String method = "validResult() ";
    msgCtxt.setVariable("message.content", simpleSoap11);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("content-encryption-cipher", "aes-192-gcm");
    props.put("certificate", "{my-certificate}");
    props.put("output-variable", "output");

    Encrypt callout = new Encrypt(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");

    verifyOutput(method, output, "http://www.w3.org/2009/xmlenc11#aes192-gcm",
                 RSA_PKCS_1_5);
  }

  @Test
  public void tripledes() throws Exception {
    String method = "validResult() ";
    msgCtxt.setVariable("message.content", simpleSoap11);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("content-encryption-cipher", "tripledes");
    props.put("certificate", "{my-certificate}");
    props.put("output-variable", "output");

    Encrypt callout = new Encrypt(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");

    verifyOutput(method, output, "http://www.w3.org/2001/04/xmlenc#tripledes-cbc",
                 RSA_PKCS_1_5);
  }

  @Test
  public void embeddedKey() throws Exception {
    String method = "validResult() ";
    msgCtxt.setVariable("message.content", simpleSoap11);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("encrypted-key-location", "under-encrypted-data");
    props.put("certificate", "{my-certificate}");
    props.put("output-variable", "output");

    Encrypt callout = new Encrypt(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");

    verifyOutput(method, output, "http://www.w3.org/2001/04/xmlenc#aes192-cbc",
                 RSA_PKCS_1_5);
  }

  @Test
  public void oaep() throws Exception {
    String method = "validResult() ";
    msgCtxt.setVariable("message.content", simpleSoap11);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("rsa-algorithm", "OAEP");
    props.put("certificate", "{my-certificate}");
    props.put("output-variable", "output");

    Encrypt callout = new Encrypt(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");

    verifyOutput(method, output, "http://www.w3.org/2001/04/xmlenc#aes192-cbc",
                 RSA_OAEP);
  }

  private void verifyOutput(String method,
                            String output,
                            String expectedEncryptionAlgorithm,
                            String rsaAlgorithm)
      throws Exception {
    System.out.printf("** Output:\n" + output + "\n");

    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));

    NodeList nl = null;

    // soap Envelope
    nl = doc.getElementsByTagNameNS(Namespaces.SOAP1_1, "Envelope");
    Assert.assertEquals(nl.getLength(), 1, method + "Envelope element");
    Element envelope = (Element) nl.item(0);

    // soap Header
    nl = envelope.getElementsByTagNameNS(Namespaces.SOAP1_1, "Header");
    Assert.assertEquals(nl.getLength(), 1, method + "Header element");
    Element header = (Element) nl.item(0);

    // Security
    nl = header.getElementsByTagNameNS(Namespaces.WSSEC, "Security");
    if (nl.getLength() == 0) throw new IllegalStateException("no Security");
    if (nl.getLength() != 1) throw new IllegalStateException("more than one Security");
    Element security = (Element) nl.item(0);

    // BinarySecurityToken - but this is not always true
    nl = security.getElementsByTagNameNS(Namespaces.WSSEC, "BinarySecurityToken");
    Assert.assertEquals(nl.getLength(), 1, method + "BST element");

    // Body
    nl = envelope.getElementsByTagNameNS(Namespaces.SOAP1_1, "Body");
    Assert.assertEquals(nl.getLength(), 1, method + "Body element");
    Element body = (Element) nl.item(0);

    // EncryptedData
    nl = body.getElementsByTagNameNS(Namespaces.XMLENC, "EncryptedData");
    Assert.assertEquals(nl.getLength(), 1, method + "EncryptedData element");
    Element encryptedData = (Element) nl.item(0);

    // EncryptedKey
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

    // (key) EncryptionMethod
    nl = encryptedKey.getElementsByTagNameNS(Namespaces.XMLENC, "EncryptionMethod");
    Assert.assertEquals(nl.getLength(), 1, method + "EncryptionMethod element");
    Element encryptionMethod = (Element) nl.item(0);
    String methodAlgorithm = encryptionMethod.getAttribute("Algorithm");

    Assert.assertEquals(methodAlgorithm, rsaAlgorithm);

    // // KeyInfo
    // nl = encryptedKey.getElementsByTagNameNS(Namespaces.XMLDSIG, "KeyInfo");
    // Assert.assertEquals(nl.getLength(), 1, method + "KeyInfo element");

    // CipherData
    nl = encryptedKey.getElementsByTagNameNS(Namespaces.XMLENC, "CipherData");
    Assert.assertEquals(nl.getLength(), 1, method + "CipherData element");

    // (content) EncryptionMethod
    encryptionMethod = getChildElementsByTagNameNS(encryptedData, Namespaces.XMLENC, "EncryptionMethod");
    Assert.assertNotNull(encryptionMethod, "encryptionMethod");

    methodAlgorithm = encryptionMethod.getAttribute("Algorithm");
    Assert.assertEquals(methodAlgorithm, expectedEncryptionAlgorithm);
  }

  public static Element getChildElementsByTagNameNS(Element e, String ns, String localName) {
    for (Node currentChild = e.getFirstChild();
        currentChild != null;
        currentChild = currentChild.getNextSibling()) {
      if (currentChild instanceof Element) {
        if (currentChild.getLocalName().equals(localName) &&
            ns.equals(currentChild.getNamespaceURI())) {
          return (Element) currentChild;
        }
      }
    }
    return null;
  }

}
