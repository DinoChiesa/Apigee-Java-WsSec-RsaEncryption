package com.google.apigee.edgecallouts.wsseccrypto;

public enum RsaAlgorithm {
  NOT_SPECIFIED,
  PKCS1_5,
  OAEP,
  OAEP1_1;

  static RsaAlgorithm fromString(String s) {
    for (RsaAlgorithm t : RsaAlgorithm.values()) {
      if (t.name().equals(s)) return t;
    }
    return RsaAlgorithm.NOT_SPECIFIED;
  }
}
