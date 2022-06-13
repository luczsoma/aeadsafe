import { assert } from "chai";
import { suite, test } from "mocha";
import { lockSafe, unlockSafe } from "../../src/aeadSafe.js";
import { checkLockSafeResultV1 } from "../testUtils.js";

const secretDataString = "secret data";
const secretDataBinary = Buffer.from(secretDataString, "utf-8");
const additionalPublicDataString = "additional public data";
const additionalPublicDataBinary = Buffer.from(
  additionalPublicDataString,
  "utf-8"
);

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
    test("should decrypt a v1 AEADSafe with secretData encrypted and additionalPublicData authenticated", () => {
      const { lockedSafe, key } = lockSafe(
        secretDataBinary,
        additionalPublicDataBinary,
        "binary",
        "binary"
      );

      const { secretData, additionalPublicData } = unlockSafe(
        key,
        lockedSafe,
        "binary"
      );

      assert.deepEqual(secretData, secretDataBinary);
      assert.deepEqual(additionalPublicData, additionalPublicDataBinary);
    });

    test("should decrypt a v1 AEADSafe with secretData encrypted and no additionalPublicData", () => {
      const { lockedSafe, key } = lockSafe(
        secretDataBinary,
        Buffer.alloc(0),
        "binary",
        "binary"
      );

      const { secretData, additionalPublicData } = unlockSafe(
        key,
        lockedSafe,
        "binary"
      );

      assert.deepEqual(secretData, secretDataBinary);
      assert.deepEqual(additionalPublicData, Buffer.alloc(0));
    });

    test("should decrypt a v1 AEADSafe with no secretData and additionalPublicData authenticated", () => {
      const { lockedSafe, key } = lockSafe(
        Buffer.alloc(0),
        additionalPublicDataBinary,
        "binary",
        "binary"
      );

      const { secretData, additionalPublicData } = unlockSafe(
        key,
        lockedSafe,
        "binary"
      );

      assert.deepEqual(secretData, Buffer.alloc(0));
      assert.deepEqual(additionalPublicData, additionalPublicDataBinary);
    });

    test("should accept binary key", () => {
      const { lockedSafe, key } = lockSafe(
        secretDataBinary,
        additionalPublicDataBinary,
        "binary",
        "binary"
      );

      const { secretData, additionalPublicData } = unlockSafe(
        key,
        lockedSafe,
        "binary"
      );

      assert.deepEqual(secretData, secretDataBinary);
      assert.deepEqual(additionalPublicData, additionalPublicDataBinary);
    });

    test("should accept base64 key", () => {
      const { lockedSafe, key } = lockSafe(
        secretDataBinary,
        additionalPublicDataBinary,
        "binary",
        "base64"
      );

      const { secretData, additionalPublicData } = unlockSafe(
        key,
        lockedSafe,
        "binary"
      );

      assert.deepEqual(secretData, secretDataBinary);
      assert.deepEqual(additionalPublicData, additionalPublicDataBinary);
    });

    test("should accept binary lockedSafe", () => {
      const { lockedSafe, key } = lockSafe(
        secretDataBinary,
        additionalPublicDataBinary,
        "binary",
        "binary"
      );

      const { secretData, additionalPublicData } = unlockSafe(
        key,
        lockedSafe,
        "binary"
      );

      assert.deepEqual(secretData, secretDataBinary);
      assert.deepEqual(additionalPublicData, additionalPublicDataBinary);
    });

    test("should accept base64 lockedSafe", () => {
      const { lockedSafe, key } = lockSafe(
        secretDataBinary,
        additionalPublicDataBinary,
        "base64",
        "binary"
      );

      const { secretData, additionalPublicData } = unlockSafe(
        key,
        lockedSafe,
        "binary"
      );

      assert.deepEqual(secretData, secretDataBinary);
      assert.deepEqual(additionalPublicData, additionalPublicDataBinary);
    });

    test("should produce binary result", () => {
      const { lockedSafe, key } = lockSafe(
        secretDataBinary,
        additionalPublicDataBinary,
        "binary",
        "binary"
      );

      const { secretData, additionalPublicData } = unlockSafe(
        key,
        lockedSafe,
        "binary"
      );

      assert.isTrue(secretData instanceof Buffer);
      assert.isTrue(additionalPublicData instanceof Buffer);

      assert.deepEqual(secretData, secretDataBinary);
      assert.deepEqual(additionalPublicData, additionalPublicDataBinary);
    });

    test("should produce string result", () => {
      const { lockedSafe, key } = lockSafe(
        secretDataString,
        additionalPublicDataString,
        "binary",
        "binary"
      );

      const { secretData, additionalPublicData } = unlockSafe(
        key,
        lockedSafe,
        "string"
      );

      assert.isTrue(typeof secretData === "string");
      assert.isTrue(typeof additionalPublicData === "string");

      assert.strictEqual(secretData, secretDataString);
      assert.strictEqual(additionalPublicData, additionalPublicDataString);
    });
  });
});
