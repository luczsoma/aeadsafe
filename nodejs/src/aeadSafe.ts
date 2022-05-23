import { AsnType, Integer, OctetString, Sequence, verifySchema } from "asn1js";
import { createCipheriv, createDecipheriv, randomBytes } from "crypto";
import { DecodedAeadSafe } from "./decodedAeadSafe";
import { EncodedAeadSafe } from "./encodedAeadSafe";
import { Encoding } from "./encoding";
import { LockSafeResult } from "./lockSafeResult";
import { UnlockSafeResult } from "./unlockSafeResult";

const AEADSAFE_VERSION = 1;

const ALGORITHM = "chacha20-poly1305";
const KEY_LENGTH_BYTES = 32;
const INITIALIZATION_VECTOR_LENGTH_BYTES = 12;
const AUTH_TAG_LENGTH_BYTES = 16;
const MAX_PLAINTEXT_LENGTH_BYTES = 2 ** 38 - 64;

const ASN1_SCHEMA = new Sequence({
  name: "AEADSafe",
  value: [
    new Integer({
      name: "AeadSafeVersion",
    }),
    new OctetString({
      name: "InitializationVector",
      isConstructed: false,
    }),
    new OctetString({
      name: "AssociatedData",
      isConstructed: false,
    }),
    new OctetString({
      name: "CipherText",
      isConstructed: false,
    }),
    new OctetString({
      name: "AuthenticationTag",
      isConstructed: false,
    }),
  ],
});

export function lockSafe(
  secretData: Buffer | string,
  additionalPublicData: Buffer | string,
  resultEncoding: "binary",
  keyEncoding: "binary"
): LockSafeResult<Buffer, Buffer>;
export function lockSafe(
  secretData: Buffer | string,
  additionalPublicData: Buffer | string,
  resultEncoding: "binary",
  keyEncoding: "base64" | "hex"
): LockSafeResult<Buffer, string>;
export function lockSafe(
  secretData: Buffer | string,
  additionalPublicData: Buffer | string,
  resultEncoding: "base64" | "hex",
  keyEncoding: "binary"
): LockSafeResult<string, Buffer>;
export function lockSafe(
  secretData: Buffer | string,
  additionalPublicData: Buffer | string,
  resultEncoding: "base64" | "hex",
  keyEncoding: "base64" | "hex"
): LockSafeResult<string, string>;
export function lockSafe(
  secretData: Buffer | string,
  additionalPublicData: Buffer | string,
  resultEncoding: Encoding,
  keyEncoding: Encoding
): LockSafeResult<Buffer | string, Buffer | string> {
  validateBufferOrString(secretData, "secretData");
  validateBufferOrString(additionalPublicData, "additionalPublicData");
  validateEncoding(resultEncoding, "resultEncoding");
  validateEncoding(keyEncoding, "keyEncoding");

  const plainText = getAsBuffer(secretData);
  validatePlainTextLength(plainText);

  const associatedData = getAsBuffer(additionalPublicData);

  const key = randomBytes(KEY_LENGTH_BYTES);
  const initializationVector = randomBytes(INITIALIZATION_VECTOR_LENGTH_BYTES);

  const cipher = createCipheriv(ALGORITHM, key, initializationVector, {
    authTagLength: AUTH_TAG_LENGTH_BYTES,
  });

  if (associatedData.length > 0) {
    cipher.setAAD(associatedData, {
      plaintextLength: plainText.length,
    });
  }

  const cipherText = Buffer.concat([cipher.update(plainText), cipher.final()]);
  const authenticationTag = cipher.getAuthTag();

  const asn1Buffer = encodeAsn1({
    aeadSafeVersion: AEADSAFE_VERSION,
    initializationVector,
    associatedData,
    cipherText,
    authenticationTag,
  });

  return {
    lockedSafe: encodeBuffer(asn1Buffer, resultEncoding),
    key: encodeBuffer(key, keyEncoding),
  };
}

export function unlockSafe(
  key: Buffer | string,
  lockedSafe: Buffer | string,
  resultEncoding: "binary"
): UnlockSafeResult<Buffer>;
export function unlockSafe(
  key: Buffer | string,
  lockedSafe: Buffer | string,
  resultEncoding: "base64" | "hex"
): UnlockSafeResult<string>;
export function unlockSafe(
  key: Buffer | string,
  lockedSafe: Buffer | string,
  resultEncoding: Encoding
): UnlockSafeResult<Buffer | string> {
  validateBufferOrString(key, "key");
  validateBufferOrString(lockedSafe, "key");
  validateEncoding(resultEncoding, "resultEncoding");

  const keyBuffer = getAsBuffer(key);
  const asn1Buffer = getAsBuffer(lockedSafe);

  const {
    initializationVector,
    associatedData,
    cipherText,
    authenticationTag,
  } = decodeAsn1(asn1Buffer);

  const decipher = createDecipheriv(
    ALGORITHM,
    keyBuffer,
    initializationVector,
    {
      authTagLength: AUTH_TAG_LENGTH_BYTES,
    }
  );

  if (associatedData.length > 0) {
    decipher.setAAD(associatedData, {
      plaintextLength: cipherText.length,
    });
  }

  decipher.setAuthTag(authenticationTag);

  const plainText = Buffer.concat([
    decipher.update(cipherText),
    decipher.final(),
  ]);

  return {
    secretData: encodeBuffer(plainText, resultEncoding),
    additionalPublicData: encodeBuffer(associatedData, resultEncoding),
  };
}

function encodeAsn1({
  aeadSafeVersion,
  initializationVector,
  associatedData,
  cipherText,
  authenticationTag,
}: DecodedAeadSafe): Buffer {
  const asn1 = new Sequence({
    value: [
      new Integer({
        value: aeadSafeVersion,
      }),
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

function decodeAsn1(asn1Buffer: Buffer): DecodedAeadSafe {
  const { verified, result } = verifySchema(asn1Buffer, ASN1_SCHEMA);
  if (!verified) {
    throw new Error("decode error");
  }

  const verifiedResult = result as AsnType & EncodedAeadSafe;

  return {
    aeadSafeVersion: verifiedResult.AeadSafeVersion.valueBlock.valueDec,
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

function validateBufferOrString(value: Buffer | string, name: string): void {
  if (!(value instanceof Buffer) && typeof value !== "string") {
    throw new Error(`${name} must be a Buffer or a literal string`);
  }
}

function validateEncoding(encoding: Encoding, name: string): void {
  switch (encoding) {
    case "binary":
    case "base64":
    case "hex":
      break;

    default:
      throw new Error(`${name} must be binary or base64 or hex`);
  }
}

function validatePlainTextLength(plainText: Buffer) {
  if (plainText.length > MAX_PLAINTEXT_LENGTH_BYTES) {
    throw new Error(
      `secretData cannot be larger than ${MAX_PLAINTEXT_LENGTH_BYTES} bytes`
    );
  }
}

function getAsBuffer(value: Buffer | string): Buffer {
  return typeof value === "string" ? Buffer.from(value, "utf-8") : value;
}

function encodeBuffer(value: Buffer, encoding: Encoding): Buffer | string {
  switch (encoding) {
    case "base64":
    case "hex":
      return value.toString(encoding);

    case "binary":
      return value;
  }
}
