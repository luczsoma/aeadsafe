import { AsnType, OctetString, Sequence, verifySchema } from "asn1js";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { AeadSafeImplementation } from "../aeadSafeImplementation.js";

export class ChaCha20Poly1305 extends AeadSafeImplementation {
  private static readonly ALGORITHM = "chacha20-poly1305";
  private static readonly KEY_LENGTH_BYTES = 32;
  private static readonly INITIALIZATION_VECTOR_LENGTH_BYTES = 12;
  private static readonly AUTH_TAG_LENGTH_BYTES = 16;
  private static readonly MAX_PLAINTEXT_LENGTH_BYTES = 2 ** 38 - 64;

  private static readonly ASN1_SCHEMA = new Sequence({
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

  public lockSafe(
    plainText: Buffer,
    associatedData: Buffer
  ): { unwrappedLockedSafe: Buffer; key: Buffer } {
    if (plainText.byteLength > ChaCha20Poly1305.MAX_PLAINTEXT_LENGTH_BYTES) {
      throw new Error(
        `plainText cannot be longer than ${ChaCha20Poly1305.MAX_PLAINTEXT_LENGTH_BYTES}`
      );
    }

    const key = randomBytes(ChaCha20Poly1305.KEY_LENGTH_BYTES);
    const initializationVector = randomBytes(
      ChaCha20Poly1305.INITIALIZATION_VECTOR_LENGTH_BYTES
    );

    const cipher = createCipheriv(
      ChaCha20Poly1305.ALGORITHM,
      key,
      initializationVector,
      {
        authTagLength: ChaCha20Poly1305.AUTH_TAG_LENGTH_BYTES,
      }
    );

    if (associatedData.length > 0) {
      cipher.setAAD(associatedData, {
        plaintextLength: plainText.length,
      });
    }

    const cipherText = Buffer.concat([
      cipher.update(plainText),
      cipher.final(),
    ]);
    const authenticationTag = cipher.getAuthTag();

    const unwrappedLockedSafe = this.encodeAsn1(
      initializationVector,
      associatedData,
      cipherText,
      authenticationTag
    );

    return { unwrappedLockedSafe, key };
  }

  public unlockSafe(
    unwrappedLockedSafe: Buffer,
    key: Buffer
  ): { plainText: Buffer; associatedData: Buffer } {
    const {
      initializationVector,
      associatedData,
      cipherText,
      authenticationTag,
    } = this.decodeAsn1(unwrappedLockedSafe);

    const decipher = createDecipheriv(
      ChaCha20Poly1305.ALGORITHM,
      key,
      initializationVector,
      {
        authTagLength: ChaCha20Poly1305.AUTH_TAG_LENGTH_BYTES,
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
      plainText,
      associatedData,
    };
  }

  private encodeAsn1(
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

  private decodeAsn1(unwrappedLockedSafe: Buffer): {
    initializationVector: Buffer;
    associatedData: Buffer;
    cipherText: Buffer;
    authenticationTag: Buffer;
  } {
    const { verified, result } = verifySchema(
      unwrappedLockedSafe,
      ChaCha20Poly1305.ASN1_SCHEMA
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
      cipherText: Buffer.from(
        verifiedResult.CipherText.valueBlock.valueHexView
      ),
      authenticationTag: Buffer.from(
        verifiedResult.AuthenticationTag.valueBlock.valueHexView
      ),
    };
  }
}
