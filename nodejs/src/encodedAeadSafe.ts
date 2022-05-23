import { Integer, OctetString } from "asn1js";

export interface EncodedAeadSafe {
  AeadSafeVersion: Integer;
  InitializationVector: OctetString;
  AssociatedData: OctetString;
  CipherText: OctetString;
  AuthenticationTag: OctetString;
}
