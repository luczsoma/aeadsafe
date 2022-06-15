import { assert } from "chai";
import { suite, test } from "mocha";
import { lockSafe, unlockSafe } from "../../src/aeadSafe.js";
import {
  checkLockSafeResultV1,
  decodeUnwrappedLockedSafeV1,
  encodeUnwrappedLockedSafeV1,
  unwrapLockedSafe,
  wrapLockedSafe,
} from "../testUtils.js";
import {
  additionalPublicDataBinary,
  additionalPublicDataString,
  secretDataBinary,
  secretDataString,
} from "../testVectors/lockSafeInputs.js";
import { lockedSafeTestVectors } from "../testVectors/unlockSafeInputs.js";

suite("AEADSafe", () => {
  suite("lockSafe", () => {
    test(
      "should create a v1 AEADSafe " +
        "with secretData encrypted and additionalPublicData authenticated",
      () => {
        const { lockedSafe, key } = lockSafe(
          secretDataBinary,
          additionalPublicDataBinary,
          "binary",
          "binary"
        );

        checkLockSafeResultV1(
          secretDataBinary,
          additionalPublicDataBinary,
          lockedSafe,
          key
        );
      }
    );

    test(
      "should create a v1 AEADSafe " +
        "with secretData encrypted and no additionalPublicData",
      () => {
        const { lockedSafe, key } = lockSafe(
          secretDataBinary,
          Buffer.alloc(0),
          "binary",
          "binary"
        );

        checkLockSafeResultV1(
          secretDataBinary,
          Buffer.alloc(0),
          lockedSafe,
          key
        );
      }
    );

    test(
      "should create a v1 AEADSafe " +
        "with no secretData and additionalPublicData authenticated",
      () => {
        const { lockedSafe, key } = lockSafe(
          Buffer.alloc(0),
          additionalPublicDataBinary,
          "binary",
          "binary"
        );

        checkLockSafeResultV1(
          Buffer.alloc(0),
          additionalPublicDataBinary,
          lockedSafe,
          key
        );
      }
    );

    test("should accept binary secretData", () => {
      const { lockedSafe, key } = lockSafe(
        secretDataBinary,
        additionalPublicDataBinary,
        "binary",
        "binary"
      );

      checkLockSafeResultV1(
        secretDataBinary,
        additionalPublicDataBinary,
        lockedSafe,
        key
      );
    });

    test("should accept string secretData", () => {
      const { lockedSafe, key } = lockSafe(
        secretDataString,
        additionalPublicDataBinary,
        "binary",
        "binary"
      );

      checkLockSafeResultV1(
        secretDataBinary,
        additionalPublicDataBinary,
        lockedSafe,
        key
      );
    });

    test("should accept binary additionalPublicData", () => {
      const { lockedSafe, key } = lockSafe(
        secretDataBinary,
        additionalPublicDataBinary,
        "binary",
        "binary"
      );

      checkLockSafeResultV1(
        secretDataBinary,
        additionalPublicDataBinary,
        lockedSafe,
        key
      );
    });

    test("should accept string additionalPublicData", () => {
      const { lockedSafe, key } = lockSafe(
        secretDataBinary,
        additionalPublicDataString,
        "binary",
        "binary"
      );

      checkLockSafeResultV1(
        secretDataBinary,
        additionalPublicDataBinary,
        lockedSafe,
        key
      );
    });

    test("should produce binary lockedSafe", () => {
      const { lockedSafe, key } = lockSafe(
        secretDataBinary,
        additionalPublicDataBinary,
        "binary",
        "binary"
      );

      assert.isTrue(lockedSafe instanceof Buffer);

      checkLockSafeResultV1(
        secretDataBinary,
        additionalPublicDataBinary,
        lockedSafe,
        key
      );
    });

    test("should produce base64 lockedSafe", () => {
      const { lockedSafe, key } = lockSafe(
        secretDataBinary,
        additionalPublicDataBinary,
        "base64",
        "binary"
      );

      assert.isTrue(typeof lockedSafe === "string");
      const lockedSafeBinary = Buffer.from(lockedSafe, "base64");

      checkLockSafeResultV1(
        secretDataBinary,
        additionalPublicDataBinary,
        lockedSafeBinary,
        key
      );
    });

    test("should produce binary key", () => {
      const { lockedSafe, key } = lockSafe(
        secretDataBinary,
        additionalPublicDataBinary,
        "binary",
        "binary"
      );

      assert.isTrue(key instanceof Buffer);

      checkLockSafeResultV1(
        secretDataBinary,
        additionalPublicDataBinary,
        lockedSafe,
        key
      );
    });

    test("should produce base64 key", () => {
      const { lockedSafe, key } = lockSafe(
        secretDataBinary,
        additionalPublicDataBinary,
        "binary",
        "base64"
      );

      assert.isTrue(typeof key === "string");
      const keyBinary = Buffer.from(key, "base64");

      checkLockSafeResultV1(
        secretDataBinary,
        additionalPublicDataBinary,
        lockedSafe,
        keyBinary
      );
    });
  });

  suite("unlockSafe", () => {
    for (const [version, testVectors] of lockedSafeTestVectors) {
      suite(
        `with ${version === 0 ? "lockSafe output" : `v${version} AEADSafe`}`,
        () => {
          test("should decrypt with secretData encrypted and additionalPublicData authenticated", () => {
            const { secretData, additionalPublicData } = unlockSafe(
              testVectors.secretDataWithAdditionalPublicData.keyBinary,
              testVectors.secretDataWithAdditionalPublicData.lockedSafeBinary,
              "binary"
            );

            assert.deepEqual(secretData, secretDataBinary);
            assert.deepEqual(additionalPublicData, additionalPublicDataBinary);
          });

          test("should decrypt with secretData encrypted and no additionalPublicData", () => {
            const { secretData, additionalPublicData } = unlockSafe(
              testVectors.secretDataOnly.keyBinary,
              testVectors.secretDataOnly.lockedSafeBinary,
              "binary"
            );

            assert.deepEqual(secretData, secretDataBinary);
            assert.deepEqual(additionalPublicData, Buffer.alloc(0));
          });

          test("should decrypt with no secretData and additionalPublicData authenticated", () => {
            const { secretData, additionalPublicData } = unlockSafe(
              testVectors.additionalPublicDataOnly.keyBinary,
              testVectors.additionalPublicDataOnly.lockedSafeBinary,
              "binary"
            );

            assert.deepEqual(secretData, Buffer.alloc(0));
            assert.deepEqual(additionalPublicData, additionalPublicDataBinary);
          });

          test("should accept binary key", () => {
            const { secretData, additionalPublicData } = unlockSafe(
              testVectors.secretDataWithAdditionalPublicData.keyBinary,
              testVectors.secretDataWithAdditionalPublicData.lockedSafeBinary,
              "binary"
            );

            assert.deepEqual(secretData, secretDataBinary);
            assert.deepEqual(additionalPublicData, additionalPublicDataBinary);
          });

          test("should accept base64 key", () => {
            const { secretData, additionalPublicData } = unlockSafe(
              testVectors.secretDataWithAdditionalPublicData.keyBase64,
              testVectors.secretDataWithAdditionalPublicData.lockedSafeBinary,
              "binary"
            );

            assert.deepEqual(secretData, secretDataBinary);
            assert.deepEqual(additionalPublicData, additionalPublicDataBinary);
          });

          test("should accept binary lockedSafe", () => {
            const { secretData, additionalPublicData } = unlockSafe(
              testVectors.secretDataWithAdditionalPublicData.keyBinary,
              testVectors.secretDataWithAdditionalPublicData.lockedSafeBinary,
              "binary"
            );

            assert.deepEqual(secretData, secretDataBinary);
            assert.deepEqual(additionalPublicData, additionalPublicDataBinary);
          });

          test("should accept base64 lockedSafe", () => {
            const { secretData, additionalPublicData } = unlockSafe(
              testVectors.secretDataWithAdditionalPublicData.keyBinary,
              testVectors.secretDataWithAdditionalPublicData.lockedSafeBase64,
              "binary"
            );

            assert.deepEqual(secretData, secretDataBinary);
            assert.deepEqual(additionalPublicData, additionalPublicDataBinary);
          });

          test("should produce binary result", () => {
            const { secretData, additionalPublicData } = unlockSafe(
              testVectors.secretDataWithAdditionalPublicData.keyBinary,
              testVectors.secretDataWithAdditionalPublicData.lockedSafeBinary,
              "binary"
            );

            assert.isTrue(secretData instanceof Buffer);
            assert.isTrue(additionalPublicData instanceof Buffer);

            assert.deepEqual(secretData, secretDataBinary);
            assert.deepEqual(additionalPublicData, additionalPublicDataBinary);
          });

          test("should produce string result", () => {
            const { secretData, additionalPublicData } = unlockSafe(
              testVectors.secretDataWithAdditionalPublicData.keyBinary,
              testVectors.secretDataWithAdditionalPublicData.lockedSafeBinary,
              "string"
            );

            assert.isTrue(typeof secretData === "string");
            assert.isTrue(typeof additionalPublicData === "string");

            assert.strictEqual(secretData, secretDataString);
            assert.strictEqual(
              additionalPublicData,
              additionalPublicDataString
            );
          });

          test("should throw on decrypting with wrong key", () => {
            const key = Buffer.from(
              testVectors.secretDataWithAdditionalPublicData.keyBinary
            );

            key[key.byteLength - 1] ^= 0x01;

            assert.throws(
              () => {
                unlockSafe(
                  key,
                  testVectors.secretDataWithAdditionalPublicData
                    .lockedSafeBinary,
                  "binary"
                );
              },
              Error,
              "Unsupported state or unable to authenticate data"
            );
          });

          test("should throw on decrypting with wrong initialization vector", () => {
            let { version, unwrappedLockedSafe } = unwrapLockedSafe(
              testVectors.secretDataWithAdditionalPublicData.lockedSafeBinary
            );
            const {
              initializationVector,
              associatedData,
              cipherText,
              authenticationTag,
            } = decodeUnwrappedLockedSafeV1(unwrappedLockedSafe);

            initializationVector[initializationVector.byteLength - 1] ^= 0x01;

            unwrappedLockedSafe = encodeUnwrappedLockedSafeV1(
              initializationVector,
              associatedData,
              cipherText,
              authenticationTag
            );

            const lockedSafeWithWrongInitializationVector = wrapLockedSafe(
              version,
              unwrappedLockedSafe
            );

            assert.throws(
              () => {
                unlockSafe(
                  testVectors.secretDataWithAdditionalPublicData.keyBinary,
                  lockedSafeWithWrongInitializationVector,
                  "binary"
                );
              },
              Error,
              "Unsupported state or unable to authenticate data"
            );
          });

          test("should throw on decrypting with wrong associated data", () => {
            let { version, unwrappedLockedSafe } = unwrapLockedSafe(
              testVectors.secretDataWithAdditionalPublicData.lockedSafeBinary
            );
            const {
              initializationVector,
              associatedData,
              cipherText,
              authenticationTag,
            } = decodeUnwrappedLockedSafeV1(unwrappedLockedSafe);

            associatedData[associatedData.byteLength - 1] ^= 0x01;

            unwrappedLockedSafe = encodeUnwrappedLockedSafeV1(
              initializationVector,
              associatedData,
              cipherText,
              authenticationTag
            );

            const lockedSafeWithWrongAssociatedData = wrapLockedSafe(
              version,
              unwrappedLockedSafe
            );

            assert.throws(
              () => {
                unlockSafe(
                  testVectors.secretDataWithAdditionalPublicData.keyBinary,
                  lockedSafeWithWrongAssociatedData,
                  "binary"
                );
              },
              Error,
              "Unsupported state or unable to authenticate data"
            );
          });

          test("should throw on decrypting with wrong ciphertext", () => {
            let { version, unwrappedLockedSafe } = unwrapLockedSafe(
              testVectors.secretDataWithAdditionalPublicData.lockedSafeBinary
            );
            const {
              initializationVector,
              associatedData,
              cipherText,
              authenticationTag,
            } = decodeUnwrappedLockedSafeV1(unwrappedLockedSafe);

            cipherText[cipherText.byteLength - 1] ^= 0x01;

            unwrappedLockedSafe = encodeUnwrappedLockedSafeV1(
              initializationVector,
              associatedData,
              cipherText,
              authenticationTag
            );

            const lockedSafeWithWrongCipherText = wrapLockedSafe(
              version,
              unwrappedLockedSafe
            );

            assert.throws(
              () => {
                unlockSafe(
                  testVectors.secretDataWithAdditionalPublicData.keyBinary,
                  lockedSafeWithWrongCipherText,
                  "binary"
                );
              },
              Error,
              "Unsupported state or unable to authenticate data"
            );
          });

          test("should throw on decrypting with wrong authentication tag", () => {
            let { version, unwrappedLockedSafe } = unwrapLockedSafe(
              testVectors.secretDataWithAdditionalPublicData.lockedSafeBinary
            );
            const {
              initializationVector,
              associatedData,
              cipherText,
              authenticationTag,
            } = decodeUnwrappedLockedSafeV1(unwrappedLockedSafe);

            authenticationTag[authenticationTag.byteLength - 1] ^= 0x01;

            unwrappedLockedSafe = encodeUnwrappedLockedSafeV1(
              initializationVector,
              associatedData,
              cipherText,
              authenticationTag
            );

            const lockedSafeWithWrongAuthenticationTag = wrapLockedSafe(
              version,
              unwrappedLockedSafe
            );

            assert.throws(
              () => {
                unlockSafe(
                  testVectors.secretDataWithAdditionalPublicData.keyBinary,
                  lockedSafeWithWrongAuthenticationTag,
                  "binary"
                );
              },
              Error,
              "Unsupported state or unable to authenticate data"
            );
          });
        }
      );
    }
  });
});
