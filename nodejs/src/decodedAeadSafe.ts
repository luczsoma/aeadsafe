export interface DecodedAeadSafe {
  aeadSafeVersion: number;
  initializationVector: Buffer;
  associatedData: Buffer;
  cipherText: Buffer;
  authenticationTag: Buffer;
}
