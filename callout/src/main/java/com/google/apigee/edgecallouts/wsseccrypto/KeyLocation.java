package com.google.apigee.edgecallouts.wsseccrypto;

public enum KeyLocation {
  NOT_SPECIFIED,
  IN_SECURITY_HEADER,
  UNDER_ENCRYPTED_DATA;

  static KeyLocation fromString(String s) {
    for (KeyLocation t : KeyLocation.values()) {
      if (t.name().equals(s)) return t;
    }
    return KeyLocation.NOT_SPECIFIED;
  }
}
