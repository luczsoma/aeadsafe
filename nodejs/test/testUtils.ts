import { AsnType, Integer, OctetString, Sequence, verifySchema } from "asn1js";
import { assert } from "chai";
import { createCipheriv } from "crypto";

export function checkLockSafeResultV1(
  secretData: Buffer,
  additionalPublicData: Buffer,
  lockedSafe: Buffer,
  key: Buffer
): void {
  const {
    version: decodedVersion,
    unwrappedLockedSafe: decodedUnwrappedLockedSafe,
  } = unwrapLockedSafe(lockedSafe);
  assert.strictEqual(decodedVersion, 1);

  const {
    initializationVector: decodedInitializationVector,
    associatedData: decodedAssociatedData,
    cipherText: decodedCipherText,
    authenticationTag: decodedAuthenticationTag,
  } = decodeUnwrappedLockedSafeV1(decodedUnwrappedLockedSafe);

  assert.strictEqual(decodedInitializationVector.length, 12);
  assert.deepEqual(decodedAssociatedData, additionalPublicData);
  assert.strictEqual(decodedCipherText.length, secretData.length);
  assert.strictEqual(decodedAuthenticationTag.length, 16);

  const cipher = createCipheriv(
    "chacha20-poly1305",
    key,
    decodedInitializationVector,
    {
      authTagLength: 16,
    }
  );

  cipher.setAAD(additionalPublicData, {
    plaintextLength: secretData.length,
  });

  const cipherText = Buffer.concat([cipher.update(secretData), cipher.final()]);
  assert.deepEqual(decodedCipherText, cipherText);

  const authenticationTag = cipher.getAuthTag();
  assert.deepEqual(decodedAuthenticationTag, authenticationTag);

  const unwrappedLockedSafe = encodeUnwrappedLockedSafeV1(
    decodedInitializationVector,
    additionalPublicData,
    cipherText,
    authenticationTag
  );
  assert.deepEqual(decodedUnwrappedLockedSafe, unwrappedLockedSafe);

  const wrappedLockedSafe = wrapLockedSafe(1, unwrappedLockedSafe);
  assert.deepEqual(lockedSafe, wrappedLockedSafe);
}

export function wrapLockedSafe(
  version: number,
  unwrappedLockedSafe: Buffer
): Buffer {
  const asn1 = new Sequence({
    value: [
      new Integer({
        value: version,
      }),
      new OctetString({
        valueHex: unwrappedLockedSafe,
      }),
    ],
  });
  const ber = asn1.toBER();
  return Buffer.from(ber);
}

export function unwrapLockedSafe(wrappedLockedSafe: Buffer): {
  version: number;
  unwrappedLockedSafe: Buffer;
} {
  const AEADSAFE_WRAPPER_ASN1_SCHEMA = new Sequence({
    name: "AEADSafeWrapper",
    value: [
      new Integer({
        name: "AEADSafeVersion",
      }),
      new OctetString({
        name: "AEADSafe",
      }),
    ],
  });

  const { verified, result } = verifySchema(
    wrappedLockedSafe,
    AEADSAFE_WRAPPER_ASN1_SCHEMA
  );

  if (!verified) {
    throw new Error("decode error");
  }

  const verifiedResult = result as AsnType & {
    AEADSafeVersion: Integer;
    AEADSafe: OctetString;
  };

  return {
    version: verifiedResult.AEADSafeVersion.valueBlock.valueDec,
    unwrappedLockedSafe: Buffer.from(
      verifiedResult.AEADSafe.valueBlock.valueHexView
    ),
  };
}

export function encodeUnwrappedLockedSafeV1(
  initializationVector: Buffer,
  associatedData: Buffer,
  cipherText: Buffer,
  authenticationTag: Buffer
): Buffer {
  const asn1 = new Sequence({
    value: [
      new OctetString({
        valueHex: initializationVector,
      }),
      new OctetString({
        valueHex: associatedData,
      }),
      new OctetString({
        valueHex: cipherText,
      }),
      new OctetString({
        valueHex: authenticationTag,
      }),
    ],
  });
  const ber = asn1.toBER();
  return Buffer.from(ber);
}

export function decodeUnwrappedLockedSafeV1(unwrappedLockedSafe: Buffer): {
  initializationVector: Buffer;
  associatedData: Buffer;
  cipherText: Buffer;
  authenticationTag: Buffer;
} {
  const AEADSAFE_V1_ASN1_SCHEMA = new Sequence({
    name: "ChaCha20Poly1305",
    value: [
      new OctetString({
        name: "InitializationVector",
      }),
      new OctetString({
        name: "AssociatedData",
      }),
      new OctetString({
        name: "CipherText",
      }),
      new OctetString({
        name: "AuthenticationTag",
      }),
    ],
  });

  const { verified, result } = verifySchema(
    unwrappedLockedSafe,
    AEADSAFE_V1_ASN1_SCHEMA
  );

  if (!verified) {
    throw new Error("decode error");
  }

  const verifiedResult = result as AsnType & {
    InitializationVector: OctetString;
    AssociatedData: OctetString;
    CipherText: OctetString;
    AuthenticationTag: OctetString;
  };

  return {
    initializationVector: Buffer.from(
      verifiedResult.InitializationVector.valueBlock.valueHexView
    ),
    associatedData: Buffer.from(
      verifiedResult.AssociatedData.valueBlock.valueHexView
    ),
    cipherText: Buffer.from(verifiedResult.CipherText.valueBlock.valueHexView),
    authenticationTag: Buffer.from(
      verifiedResult.AuthenticationTag.valueBlock.valueHexView
    ),
  };
}
