package com.google.apigee.edgecallouts.test;

import com.apigee.flow.execution.ExecutionResult;
import com.google.apigee.edgecallouts.wsseccrypto.Decrypt;
import java.util.HashMap;
import java.util.Map;
import org.testng.Assert;
import org.testng.annotations.Test;

public class TestWssecDecryptCallout extends CalloutTestBase {

  private static final String emptyDocument = "";

  private static final String encryptedSoap1_keyInEncryptedData = ""
+"<soapenv:Envelope\n"
+"    xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"\n"
+"    xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"\n"
+"    xmlns:ns1=\"http://ws.example.com/\"\n"
+"    xmlns:wssec=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"\n"
+"    xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"\n"
+"    xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\">\n"
+"  <soapenv:Header>\n"
+"    <wssec:Security soapenv:mustUnderstand=\"1\">\n"
+"      <wssec:BinarySecurityToken EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\" wsu:Id=\"SecurityToken-49b58c69-c524-48cb-b515-f2a21ae66c59\">MIIDpDCCAowCCQDsXkZg2rbAwTANBgkqhkiG9w0BAQUFADCBkzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xETAPBgNVBAcMCEtpcmtsYW5kMQ8wDQYDVQQKDAZHb29nbGUxDzANBgNVBAsMBkFwaWdlZTEaMBgGA1UEAwwRYXBpZ2VlLmdvb2dsZS5jb20xHjAcBgkqhkiG9w0BCQEWD2Rpbm9AYXBpZ2VlLmNvbTAeFw0xOTEwMDgxMTExMjBaFw0yOTEwMDUxMTExMjBaMIGTMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjERMA8GA1UEBwwIS2lya2xhbmQxDzANBgNVBAoMBkdvb2dsZTEPMA0GA1UECwwGQXBpZ2VlMRowGAYDVQQDDBFhcGlnZWUuZ29vZ2xlLmNvbTEeMBwGCSqGSIb3DQEJARYPZGlub0BhcGlnZWUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqJA2NwXeqXaVaHO0mkKDpTdhPCh/80gH2Oun4DJOYjYgvdMRJ83xB6Hwm809T593rkX9PwOjUDQ7kJvH0aLaqxb+FrrTDTFcXZXJZ65dca9lYARxgEAwasPIkvBdr0nP2W2VQgPKtkwStZinMiJh/JSlXCz7ULDGVqW8FyklGaVIkxrXhHsjH+hhJ8Kp+zjFsfdsTkGbaqXj/qexeHUBcF6GbHe7xhaLoj/P24D7mFHB3uXx4vN3ohP+ZiT1y5X8fCLVu5SSC+vDFHR2Z5I26yTlcNRwKt24lNypGsEzM5KZILJlEr3BnAA1qkcSX7wZQDHp3XOHJHaR6lxarvYlmQIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQBD+S4bF8b07955E7HshWFez5Q4/7cXhGPjFaiNw9lH9Ny1iIcblRl36iiVda4Lemy1Kxa5xGJ+I5NZ8k1MyxZ1x5K9bPX5LiI8ThLGRxBNUNLgaoQ+7FZLklpZARoIuQ3Gg90V0qUqkm2eipgZxzdtEGj+lqoX10A2B+wimO6nzUv6vYoJARMBtqsYmQKz5GRBoajGdMn60UF9Ry5B32k31JVpat4qm7+Ig1YMwv2nfY6bgHzsI4WjETOLvFCYgBDJzIEy+0jA1FUe5Ec5Fs5nmiG8F7FRJ/9aYb1e+cbQVRZyc1wKlmIReK/LgG8FjdDjeqFZTg0AjInG8/oOz5ib</wssec:BinarySecurityToken>\n"
+"    </wssec:Security>\n"
+"  </soapenv:Header>\n"
+"  <soapenv:Body wsu:Id=\"Body-cc9a2d41-a320-49b9-9db5-4af4478aba79\">\n"
+"    <xenc:EncryptedData Id=\"Enc-1\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\">\n"
+"      <xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes192-cbc\"/>\n"
+"      <ds:KeyInfo>\n"
+"        <wssec:SecurityTokenReference>\n"
+"          <wssec:Reference URI=\"#SecurityToken-49b58c69-c524-48cb-b515-f2a21ae66c59\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\"/>\n"
+"        </wssec:SecurityTokenReference>\n"
+"        <xenc:EncryptedKey>\n"
+"          <xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-1_5\"/>\n"
+"          <xenc:CipherData>\n"
+"            <xenc:CipherValue>SHhosWQtTkocucQffDx6F33N6y+1thOj794Dr9d9321+d4qzu4J//4620XuG9U4myYvP2rIMJ2P5&#13;\n"
+"            Z1JV/liuRVWQTw14CoS8M5EMJf/ov85FKLo8aeryJZ5Vinu9HhlSGfsrJNQxmkKkgh2B2poxVjte&#13;\n"
+"            j91SAmj2EoS3ORW+1toJP8XsDohN0je3y2kECVUay4xxwhDB8veKOYNA4sIx8rFsj79Gr6mjBt0o&#13;\n"
+"            da1WV0hTeA7t4miS2ANkLakTDvYNrTyu6knjhwwASOOoveFcCUUEA3cz3xyp+mUPM8IyYbrAKRDC&#13;\n"
+"            zKZXAYTcCvsy+jMgYT4yTQu4YLFmNY/JkGKF3Q==</xenc:CipherValue>\n"
+"          </xenc:CipherData>\n"
+"        </xenc:EncryptedKey>\n"
+"      </ds:KeyInfo>\n"
+"      <xenc:CipherData>\n"
+"        <xenc:CipherValue>hg+Q04MSrPRahz54m+hpJxcNdW/kmKu2pCPJ0XcPcVgQV0pwDMyxHvThWTSSRvWFTfd3QGKsgiRf&#13;\n"
+"        POx/aa4GEKbsRMUABTIUmEkapVdDTxBNZ1v2vTIlPmv2UMuj9axN</xenc:CipherValue>\n"
+"      </xenc:CipherData>\n"
+"    </xenc:EncryptedData>\n"
+"  </soapenv:Body>\n"
    +"</soapenv:Envelope>\n";

  private static final String encryptedSoap2_keyInHeader = ""

+"<soapenv:Envelope\n"
+"    xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"\n"
+"    xmlns:ns1=\"http://ws.example.com/\"\n"
+"    xmlns:wssec=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"\n"
+"    xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">\n"
+"  <soapenv:Header>\n"
+"    <wssec:Security soapenv:mustUnderstand=\"1\">\n"
+"      <wssec:BinarySecurityToken EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\" wsu:Id=\"SecurityToken-56109295-0568-41f8-8833-78a53f4e0321\">MIIDpDCCAowCCQDsXkZg2rbAwTANBgkqhkiG9w0BAQUFADCBkzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xETAPBgNVBAcMCEtpcmtsYW5kMQ8wDQYDVQQKDAZHb29nbGUxDzANBgNVBAsMBkFwaWdlZTEaMBgGA1UEAwwRYXBpZ2VlLmdvb2dsZS5jb20xHjAcBgkqhkiG9w0BCQEWD2Rpbm9AYXBpZ2VlLmNvbTAeFw0xOTEwMDgxMTExMjBaFw0yOTEwMDUxMTExMjBaMIGTMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjERMA8GA1UEBwwIS2lya2xhbmQxDzANBgNVBAoMBkdvb2dsZTEPMA0GA1UECwwGQXBpZ2VlMRowGAYDVQQDDBFhcGlnZWUuZ29vZ2xlLmNvbTEeMBwGCSqGSIb3DQEJARYPZGlub0BhcGlnZWUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqJA2NwXeqXaVaHO0mkKDpTdhPCh/80gH2Oun4DJOYjYgvdMRJ83xB6Hwm809T593rkX9PwOjUDQ7kJvH0aLaqxb+FrrTDTFcXZXJZ65dca9lYARxgEAwasPIkvBdr0nP2W2VQgPKtkwStZinMiJh/JSlXCz7ULDGVqW8FyklGaVIkxrXhHsjH+hhJ8Kp+zjFsfdsTkGbaqXj/qexeHUBcF6GbHe7xhaLoj/P24D7mFHB3uXx4vN3ohP+ZiT1y5X8fCLVu5SSC+vDFHR2Z5I26yTlcNRwKt24lNypGsEzM5KZILJlEr3BnAA1qkcSX7wZQDHp3XOHJHaR6lxarvYlmQIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQBD+S4bF8b07955E7HshWFez5Q4/7cXhGPjFaiNw9lH9Ny1iIcblRl36iiVda4Lemy1Kxa5xGJ+I5NZ8k1MyxZ1x5K9bPX5LiI8ThLGRxBNUNLgaoQ+7FZLklpZARoIuQ3Gg90V0qUqkm2eipgZxzdtEGj+lqoX10A2B+wimO6nzUv6vYoJARMBtqsYmQKz5GRBoajGdMn60UF9Ry5B32k31JVpat4qm7+Ig1YMwv2nfY6bgHzsI4WjETOLvFCYgBDJzIEy+0jA1FUe5Ec5Fs5nmiG8F7FRJ/9aYb1e+cbQVRZyc1wKlmIReK/LgG8FjdDjeqFZTg0AjInG8/oOz5ib</wssec:BinarySecurityToken>\n"
+"      <xenc:EncryptedKey\n"
+"          xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\">\n"
+"        <xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-1_5\"/>\n"
+"        <ds:KeyInfo\n"
+"            xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n"
+"          <wssec:SecurityTokenReference>\n"
+"            <wssec:Reference URI=\"#SecurityToken-56109295-0568-41f8-8833-78a53f4e0321\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\"/>\n"
+"          </wssec:SecurityTokenReference>\n"
+"        </ds:KeyInfo>\n"
+"        <xenc:CipherData>\n"
+"          <xenc:CipherValue>nX54KICG7l6fz7p3w2BFGW4EY6+QVtYj/ZtJLYiP1a12o8jnooFbXNOkQomAP3hR9ZSpd5v6qWGh&#13;\n"
+"          zDfzAq6TbBX6bTZdTirkApE99bgictQ4+tVoPJlJYQkEACD9GDc2BFQDhXLSWStgDboKNRFCyDZj&#13;\n"
+"          AtNUIwcfnno6oUzJ/V4PEJqRH7Ji8VH/sj62UlgJsRk2+rFH+v5UuRXLEgVooM33uNTahaNiirET&#13;\n"
+"          hYTov1SGPEI9JT3Dte06fdCb3L/NP7E7JvFvyZC0eJDxl4hwsHweoJroFnfdUctcMR3c648IASLz&#13;\n"
+"          WKOPS+StSgAmbhLN7XC/sf9dqSCgiVvCcOMwng==</xenc:CipherValue>\n"
+"        </xenc:CipherData>\n"
+"      </xenc:EncryptedKey>\n"
+"    </wssec:Security>\n"
+"  </soapenv:Header>\n"
+"  <soapenv:Body wsu:Id=\"Body-af8bf368-f901-4a8a-a6b1-f738b90c0bea\">\n"
+"    <xenc:EncryptedData\n"
+"        xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\">\n"
+"      <xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes192-cbc\"/>\n"
+"      <xenc:CipherData>\n"
+"        <xenc:CipherValue>C350uV99JDKp1YustgY9I27X5nr53iXp7vCQ+XI3S33jbR2wqLZdkCtFv/aSuNvCNRXhunrBjpSe&#13;\n"
+"        saF/npRMx2eJo22+l7bCf3EFIOuJxQMiUJfp7TrQnjExqIs5zONm</xenc:CipherValue>\n"
+"      </xenc:CipherData>\n"
+"    </xenc:EncryptedData>\n"
+"  </soapenv:Body>\n"
    +"</soapenv:Envelope>\n";

  private static final String encryptedSoap3_oaep = ""

+"<soapenv:Envelope\n"
+"    xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"\n"
+"    xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"\n"
+"    xmlns:ns1=\"http://ws.example.com/\"\n"
+"    xmlns:wssec=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"\n"
+"    xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"\n"
+"    xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\">\n"
+"  <soapenv:Header>\n"
+"    <wssec:Security soapenv:mustUnderstand=\"1\">\n"
+"      <wssec:BinarySecurityToken EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\" wsu:Id=\"SecurityToken-0dcdabf8-595b-47b6-86c7-8d33290279ce\">MIIDpDCCAowCCQDsXkZg2rbAwTANBgkqhkiG9w0BAQUFADCBkzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xETAPBgNVBAcMCEtpcmtsYW5kMQ8wDQYDVQQKDAZHb29nbGUxDzANBgNVBAsMBkFwaWdlZTEaMBgGA1UEAwwRYXBpZ2VlLmdvb2dsZS5jb20xHjAcBgkqhkiG9w0BCQEWD2Rpbm9AYXBpZ2VlLmNvbTAeFw0xOTEwMDgxMTExMjBaFw0yOTEwMDUxMTExMjBaMIGTMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjERMA8GA1UEBwwIS2lya2xhbmQxDzANBgNVBAoMBkdvb2dsZTEPMA0GA1UECwwGQXBpZ2VlMRowGAYDVQQDDBFhcGlnZWUuZ29vZ2xlLmNvbTEeMBwGCSqGSIb3DQEJARYPZGlub0BhcGlnZWUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqJA2NwXeqXaVaHO0mkKDpTdhPCh/80gH2Oun4DJOYjYgvdMRJ83xB6Hwm809T593rkX9PwOjUDQ7kJvH0aLaqxb+FrrTDTFcXZXJZ65dca9lYARxgEAwasPIkvBdr0nP2W2VQgPKtkwStZinMiJh/JSlXCz7ULDGVqW8FyklGaVIkxrXhHsjH+hhJ8Kp+zjFsfdsTkGbaqXj/qexeHUBcF6GbHe7xhaLoj/P24D7mFHB3uXx4vN3ohP+ZiT1y5X8fCLVu5SSC+vDFHR2Z5I26yTlcNRwKt24lNypGsEzM5KZILJlEr3BnAA1qkcSX7wZQDHp3XOHJHaR6lxarvYlmQIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQBD+S4bF8b07955E7HshWFez5Q4/7cXhGPjFaiNw9lH9Ny1iIcblRl36iiVda4Lemy1Kxa5xGJ+I5NZ8k1MyxZ1x5K9bPX5LiI8ThLGRxBNUNLgaoQ+7FZLklpZARoIuQ3Gg90V0qUqkm2eipgZxzdtEGj+lqoX10A2B+wimO6nzUv6vYoJARMBtqsYmQKz5GRBoajGdMn60UF9Ry5B32k31JVpat4qm7+Ig1YMwv2nfY6bgHzsI4WjETOLvFCYgBDJzIEy+0jA1FUe5Ec5Fs5nmiG8F7FRJ/9aYb1e+cbQVRZyc1wKlmIReK/LgG8FjdDjeqFZTg0AjInG8/oOz5ib</wssec:BinarySecurityToken>\n"
+"      <xenc:EncryptedKey>\n"
+"        <xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"/>\n"
+"        <ds:KeyInfo>\n"
+"          <wssec:SecurityTokenReference>\n"
+"            <wssec:Reference URI=\"#SecurityToken-0dcdabf8-595b-47b6-86c7-8d33290279ce\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\"/>\n"
+"          </wssec:SecurityTokenReference>\n"
+"        </ds:KeyInfo>\n"
+"        <xenc:CipherData>\n"
+"          <xenc:CipherValue>NbTLg5WzYDuWzZfoKlg9C05acTPn27aeKdibP4UxP2hFq3FzyxXz5bnCaHFQmuYjGEA/4RQ7c/vz&#13;\n"
+"          bA8pdqMGTGcvancBQzsK583yVw91EoeZT0py/KiNkDhRRxnYvRpHROIySYVMcH5lG33N7VGqyAIG&#13;\n"
+"          vrrsV2EOHO4LU+BUgvL0lY3L1NQjxJY9ixs+4/6JNXg1x6fICRtra5lXozdHNLeRWTsaIMBRDy08&#13;\n"
+"          +iltpva8mws47jY3QHIGrwiCPNSSSyNk1d6HLeVStJ6zIC9B8o96owBDX/VybEM6xOWkHxgi0kkt&#13;\n"
+"          BL1G7hJrEvAuqxIeNqDGTYDcTSI/jbleSC1cGA==</xenc:CipherValue>\n"
+"        </xenc:CipherData>\n"
+"        <xenc:ReferenceList>\n"
+"          <xenc:DataReference URI=\"#Enc-1\"/>\n"
+"        </xenc:ReferenceList>\n"
+"      </xenc:EncryptedKey>\n"
+"    </wssec:Security>\n"
+"  </soapenv:Header>\n"
+"  <soapenv:Body wsu:Id=\"Body-1c7d3689-5f34-4ede-b63f-25bf9504daa9\">\n"
+"    <xenc:EncryptedData Id=\"Enc-1\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\">\n"
+"      <xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes192-cbc\"/>\n"
+"      <xenc:CipherData>\n"
+"        <xenc:CipherValue>JOdu2WQgCdx1v7J/oTNexEk4CtmrA41+ZIIGQFHED0B3gKrQKL9uGRRXurjAa67hoVLq0oyUT1ga&#13;\n"
+"        0zF76Ppt2/ua21XU1fHgXWOmv8yFRWEX3ijhkcVbQzEbssq+jWHc</xenc:CipherValue>\n"
+"      </xenc:CipherData>\n"
+"    </xenc:EncryptedData>\n"
+"  </soapenv:Body>\n"
    +"</soapenv:Envelope>\n";

  private static final String encryptedSoap0 = ""
    + "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:ns1=\"http://ws.example.com/\" xmlns:wssec=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\">  <soapenv:Header><wssec:Security soapenv:mustUnderstand=\"1\"><wssec:BinarySecurityToken EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\" wsu:Id=\"SecurityToken-d462c660-0a3f-42b4-9ced-b2a654d2cab8\">MIIDpDCCAowCCQDsXkZg2rbAwTANBgkqhkiG9w0BAQUFADCBkzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xETAPBgNVBAcMCEtpcmtsYW5kMQ8wDQYDVQQKDAZHb29nbGUxDzANBgNVBAsMBkFwaWdlZTEaMBgGA1UEAwwRYXBpZ2VlLmdvb2dsZS5jb20xHjAcBgkqhkiG9w0BCQEWD2Rpbm9AYXBpZ2VlLmNvbTAeFw0xOTEwMDgxMTExMjBaFw0yOTEwMDUxMTExMjBaMIGTMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjERMA8GA1UEBwwIS2lya2xhbmQxDzANBgNVBAoMBkdvb2dsZTEPMA0GA1UECwwGQXBpZ2VlMRowGAYDVQQDDBFhcGlnZWUuZ29vZ2xlLmNvbTEeMBwGCSqGSIb3DQEJARYPZGlub0BhcGlnZWUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqJA2NwXeqXaVaHO0mkKDpTdhPCh/80gH2Oun4DJOYjYgvdMRJ83xB6Hwm809T593rkX9PwOjUDQ7kJvH0aLaqxb+FrrTDTFcXZXJZ65dca9lYARxgEAwasPIkvBdr0nP2W2VQgPKtkwStZinMiJh/JSlXCz7ULDGVqW8FyklGaVIkxrXhHsjH+hhJ8Kp+zjFsfdsTkGbaqXj/qexeHUBcF6GbHe7xhaLoj/P24D7mFHB3uXx4vN3ohP+ZiT1y5X8fCLVu5SSC+vDFHR2Z5I26yTlcNRwKt24lNypGsEzM5KZILJlEr3BnAA1qkcSX7wZQDHp3XOHJHaR6lxarvYlmQIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQBD+S4bF8b07955E7HshWFez5Q4/7cXhGPjFaiNw9lH9Ny1iIcblRl36iiVda4Lemy1Kxa5xGJ+I5NZ8k1MyxZ1x5K9bPX5LiI8ThLGRxBNUNLgaoQ+7FZLklpZARoIuQ3Gg90V0qUqkm2eipgZxzdtEGj+lqoX10A2B+wimO6nzUv6vYoJARMBtqsYmQKz5GRBoajGdMn60UF9Ry5B32k31JVpat4qm7+Ig1YMwv2nfY6bgHzsI4WjETOLvFCYgBDJzIEy+0jA1FUe5Ec5Fs5nmiG8F7FRJ/9aYb1e+cbQVRZyc1wKlmIReK/LgG8FjdDjeqFZTg0AjInG8/oOz5ib</wssec:BinarySecurityToken><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-1_5\"/><ds:KeyInfo>"
+ "<wssec:SecurityTokenReference><wssec:Reference URI=\"#SecurityToken-d462c660-0a3f-42b4-9ced-b2a654d2cab8\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\"/></wssec:SecurityTokenReference>"
+ "</ds:KeyInfo><xenc:CipherData><xenc:CipherValue>AvOw4fc5HlRUXxwfssISBsmB9Go+1/R3fP8yMlD6Nu7nh03EAf9e5dxsCGRyXWKpX05PAQhBKWMV&#13;"
+ "2BOKOvDcNN7HrWEXiloZVWO8spGCyLjHduWxALtg4nlwda/1i5zdpVJ3c+iuvIJI5EDhKnUzrWDV&#13;"
+ "eHLjVDQ8UNySVLjYBvwb6Bt4Vsy7EpF2mDKyRWm34tGTMj5WbcjJv478elMiEqrH8v2x8UHlRSs6&#13;"
+ "uR6VlAWqVeSIOLO+xcmreT7eVzfoOa8+yZJImD5TKrQxm+HOGJt8EKXRO/FxDpDZCEesrU1R/wKy&#13;"
+    "ABG2cF/7Mt/YwgmeQiq6JFP4L39BAucHY7dnkQ==</xenc:CipherValue></xenc:CipherData><xenc:ReferenceList><xenc:DataReference URI=\"#Enc-1\"/></xenc:ReferenceList></xenc:EncryptedKey></wssec:Security></soapenv:Header><soapenv:Body wsu:Id=\"Body-09707298-0f25-4458-9b22-9830fc585c78\">    <xenc:EncryptedData Id=\"Enc-1\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes192-cbc\"/><xenc:CipherData><xenc:CipherValue>ts5g43QSKtQ8FEevUNQMgHJz9bCf8JTrCN+2swKa0xdhlumwol2cOfpk3s0a6EfzAaoSLx5xpppy&#13;"
+    "T/7VzhFlatlqUP6JURoOXgpUzexAIi0Gjb0RMxlbNdldbVKdx2Uc</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>  </soapenv:Body></soapenv:Envelope>";


  @Test
  public void emptySource() throws Exception {
    String expectedError = "source variable resolves to null";
    msgCtxt.setVariable("message-content", encryptedSoap1_keyInEncryptedData);

    Map<String, String> props = new HashMap<String, String>();
    props.put("source", "not-message.content");

    Decrypt callout = new Decrypt(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNotNull(errorOutput, "errorOutput");
    Assert.assertEquals(errorOutput, expectedError, "error not as expected");

    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, "stacktrace");
  }

  @Test
  public void missingPrivateKey() throws Exception {
    String method = "missingPrivateKey() ";
    String expectedError = "private-key resolves to an empty string";
    msgCtxt.setVariable("message.content", encryptedSoap1_keyInEncryptedData);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");

    Decrypt callout = new Decrypt(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNotNull(errorOutput, "errorOutput");
    Assert.assertEquals(errorOutput, expectedError, "error not as expected");

    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");
  }

  @Test
  public void keyInEncryptedData() throws Exception {
    String method = "keyInEncryptedData() ";
    msgCtxt.setVariable("message.content", encryptedSoap1_keyInEncryptedData);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("private-key", "{my-private-key}");

    Decrypt callout = new Decrypt(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "errorOutput");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    // todo: validate the expected output XML content
  }

  @Test
  public void keyInHeader() throws Exception {
    String method = "keyInHeader() ";
    msgCtxt.setVariable("message.content", encryptedSoap2_keyInHeader);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("private-key", "{my-private-key}");

    Decrypt callout = new Decrypt(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "errorOutput");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    // todo: validate the expected output XML content
  }

  @Test
  public void oaep() throws Exception {
    String method = "oaep() ";
    msgCtxt.setVariable("message.content", encryptedSoap3_oaep);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("private-key", "{my-private-key}");

    Decrypt callout = new Decrypt(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "errorOutput");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    // todo: validate the expected output XML content
  }

}
