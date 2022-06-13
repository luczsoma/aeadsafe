import { AsnType, Integer, OctetString, Sequence, verifySchema } from "asn1js";
import type { AeadSafeImplementation } from "./aeadSafeImplementation.js";
import { ChaCha20Poly1305 } from "./implementation/chaCha20Poly1305.js";
import type { KeyEncoding } from "./keyEncoding.js";
import { keyEncodings } from "./keyEncoding.js";
import type { LockedSafeEncoding } from "./lockedSafeEncoding.js";
import { lockedSafeEncodings } from "./lockedSafeEncoding.js";
import type { LockSafeResult } from "./lockSafeResult.js";
import type { UnlockedSafeEncoding } from "./unlockedSafeEncoding.js";
import { unlockedSafeEncodings } from "./unlockedSafeEncoding.js";
import type { UnlockSafeResult } from "./unlockSafeResult.js";

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

const AEADSAFE_VERSIONS: ReadonlyMap<number, AeadSafeImplementation> = new Map([
  [1, new ChaCha20Poly1305()],
]);

export function lockSafe(
  secretData: Buffer | string,
  additionalPublicData: Buffer | string,
  lockedSafeEncoding: "binary",
  keyEncoding: "binary"
): LockSafeResult<Buffer, Buffer>;
export function lockSafe(
  secretData: Buffer | string,
  additionalPublicData: Buffer | string,
  lockedSafeEncoding: "binary",
  keyEncoding: "base64"
): LockSafeResult<Buffer, string>;
export function lockSafe(
  secretData: Buffer | string,
  additionalPublicData: Buffer | string,
  lockedSafeEncoding: "base64",
  keyEncoding: "binary"
): LockSafeResult<string, Buffer>;
export function lockSafe(
  secretData: Buffer | string,
  additionalPublicData: Buffer | string,
  lockedSafeEncoding: "base64",
  keyEncoding: "base64"
): LockSafeResult<string, string>;
export function lockSafe(
  secretData: Buffer | string,
  additionalPublicData: Buffer | string,
  lockedSafeEncoding: LockedSafeEncoding,
  keyEncoding: KeyEncoding
): LockSafeResult<Buffer | string, Buffer | string> {
  validateBufferOrString(secretData, "secretData");
  validateBufferOrString(additionalPublicData, "additionalPublicData");
  validateValue(lockedSafeEncoding, lockedSafeEncodings, "lockedSafeEncoding");
  validateValue(keyEncoding, keyEncodings, "keyEncoding");

  const latestAeadSafeVersion = Math.max(...AEADSAFE_VERSIONS.keys());
  const latestAeadSafeImplementation = AEADSAFE_VERSIONS.get(
    latestAeadSafeVersion
  );
  if (latestAeadSafeImplementation === undefined) {
    throw new Error("version not found");
  }

  const plainText = getBufferOrStringAsBuffer(secretData);
  const associatedData = getBufferOrStringAsBuffer(additionalPublicData);

  const { unwrappedLockedSafe, key } = latestAeadSafeImplementation.lockSafe(
    plainText,
    associatedData
  );

  const wrappedLockedSafe = wrapLockedSafe(
    latestAeadSafeVersion,
    unwrappedLockedSafe
  );

  return {
    lockedSafe: encodeBuffer(wrappedLockedSafe, lockedSafeEncoding),
    key: encodeBuffer(key, keyEncoding),
  };
}

export function unlockSafe(
  key: Buffer | string,
  lockedSafe: Buffer | string,
  unlockedSafeEncoding: "binary"
): UnlockSafeResult<Buffer>;
export function unlockSafe(
  key: Buffer | string,
  lockedSafe: Buffer | string,
  unlockedSafeEncoding: "string"
): UnlockSafeResult<string>;
export function unlockSafe(
  key: Buffer | string,
  lockedSafe: Buffer | string,
  unlockedSafeEncoding: UnlockedSafeEncoding
): UnlockSafeResult<Buffer | string> {
  validateBufferOrString(key, "key");
  validateBufferOrString(lockedSafe, "key");
  validateValue(
    unlockedSafeEncoding,
    unlockedSafeEncodings,
    "unlockedSafeEncoding"
  );

  const wrappedLockedSafe = decodeBuffer(lockedSafe);
  const { version, unwrappedLockedSafe } = unwrapLockedSafe(wrappedLockedSafe);

  const aeadSafeImplementation = AEADSAFE_VERSIONS.get(version);
  if (aeadSafeImplementation === undefined) {
    throw new Error("version not found");
  }

  const keyBytes = decodeBuffer(key);
  const { plainText, associatedData } = aeadSafeImplementation.unlockSafe(
    unwrappedLockedSafe,
    keyBytes
  );

  return {
    secretData: encodeBuffer(plainText, unlockedSafeEncoding),
    additionalPublicData: encodeBuffer(associatedData, unlockedSafeEncoding),
  };
}

function wrapLockedSafe(version: number, unwrappedLockedSafe: Buffer): Buffer {
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

function unwrapLockedSafe(wrappedLockedSafe: Buffer): {
  version: number;
  unwrappedLockedSafe: Buffer;
} {
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

function validateBufferOrString(value: any, name: string): void {
  if (!(value instanceof Buffer) && typeof value !== "string") {
    throw new Error(`${name} must be a Buffer or a literal string`);
  }
}

function validateValue(
  value: any,
  validValues: readonly any[],
  name: string
): void {
  if (!validValues.includes(value)) {
    throw new Error(
      `${name} must be one of the following: ${validValues.join(", ")}`
    );
  }
}

function getBufferOrStringAsBuffer(value: Buffer | string): Buffer {
  return typeof value === "string" ? Buffer.from(value, "utf-8") : value;
}

function decodeBuffer(value: Buffer | string): Buffer {
  return typeof value === "string" ? Buffer.from(value, "base64") : value;
}

function encodeBuffer(
  value: Buffer,
  encoding: LockedSafeEncoding | UnlockedSafeEncoding
): Buffer | string {
  switch (encoding) {
    case "string":
      return value.toString("utf-8");

    case "base64":
      return value.toString(encoding);

    case "binary":
      return value;
  }
}
