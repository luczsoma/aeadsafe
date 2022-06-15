import { lockSafe } from "../../src/aeadSafe.js";
import { LockedSafeTestVector } from "./lockedSafeTestVector.js";
import { LockedSafeTestVectors } from "./lockedSafeTestVectors.js";
import {
  additionalPublicDataBinary,
  secretDataBinary,
} from "./lockSafeInputs.js";

function generateLockSafeTestVector(
  secretData: Buffer,
  additionalPublicData: Buffer
): LockedSafeTestVector {
  const { lockedSafe, key } = lockSafe(
    secretData,
    additionalPublicData,
    "binary",
    "binary"
  );
  return {
    lockedSafeBinary: lockedSafe,
    lockedSafeBase64: lockedSafe.toString("base64"),
    keyBinary: key,
    keyBase64: key.toString("base64"),
  };
}

export const lockedSafeTestVectors = new Map<number, LockedSafeTestVectors>([
  [
    0,
    {
      secretDataOnly: generateLockSafeTestVector(
        secretDataBinary,
        Buffer.alloc(0)
      ),
      additionalPublicDataOnly: generateLockSafeTestVector(
        Buffer.alloc(0),
        additionalPublicDataBinary
      ),
      secretDataWithAdditionalPublicData: generateLockSafeTestVector(
        secretDataBinary,
        additionalPublicDataBinary
      ),
    },
  ],
  [
    1,
    {
      secretDataOnly: {
        lockedSafeBinary: Buffer.from([
          48, 54, 2, 1, 1, 4, 49, 48, 47, 4, 12, 24, 117, 51, 247, 55, 144, 206,
          228, 254, 63, 215, 116, 4, 0, 4, 11, 125, 232, 230, 39, 77, 240, 48,
          107, 16, 119, 111, 4, 16, 115, 199, 132, 69, 231, 223, 11, 254, 249,
          213, 219, 174, 9, 11, 77, 220,
        ]),
        lockedSafeBase64:
          "MDYCAQEEMTAvBAwYdTP3N5DO5P4/13QEAAQLfejmJ03wMGsQd28EEHPHhEXn3wv++dXbrgkLTdw=",
        keyBinary: Buffer.from([
          151, 3, 164, 109, 35, 100, 93, 144, 206, 229, 94, 174, 232, 96, 87,
          248, 16, 235, 93, 224, 25, 195, 193, 185, 77, 60, 47, 14, 204, 179, 6,
          46,
        ]),
        keyBase64: "lwOkbSNkXZDO5V6u6GBX+BDrXeAZw8G5TTwvDsyzBi4=",
      },
      additionalPublicDataOnly: {
        lockedSafeBinary: Buffer.from([
          48, 65, 2, 1, 1, 4, 60, 48, 58, 4, 12, 17, 226, 179, 237, 47, 232,
          153, 199, 204, 212, 32, 143, 4, 22, 97, 100, 100, 105, 116, 105, 111,
          110, 97, 108, 32, 112, 117, 98, 108, 105, 99, 32, 100, 97, 116, 97, 4,
          0, 4, 16, 120, 12, 0, 34, 173, 42, 118, 150, 11, 237, 19, 74, 11, 193,
          209, 101,
        ]),
        lockedSafeBase64:
          "MEECAQEEPDA6BAwR4rPtL+iZx8zUII8EFmFkZGl0aW9uYWwgcHVibGljIGRhdGEEAAQQeAwAIq0qdpYL7RNKC8HRZQ==",
        keyBinary: Buffer.from([
          230, 157, 212, 129, 252, 38, 155, 142, 180, 198, 37, 60, 200, 249,
          143, 155, 182, 199, 212, 186, 145, 78, 181, 100, 195, 59, 152, 204,
          238, 183, 37, 243,
        ]),
        keyBase64: "5p3Ugfwmm460xiU8yPmPm7bH1LqRTrVkwzuYzO63JfM=",
      },
      secretDataWithAdditionalPublicData: {
        lockedSafeBinary: Buffer.from([
          48, 76, 2, 1, 1, 4, 71, 48, 69, 4, 12, 87, 133, 119, 159, 0, 137, 137,
          94, 112, 227, 206, 164, 4, 22, 97, 100, 100, 105, 116, 105, 111, 110,
          97, 108, 32, 112, 117, 98, 108, 105, 99, 32, 100, 97, 116, 97, 4, 11,
          234, 76, 129, 128, 195, 75, 236, 245, 202, 77, 167, 4, 16, 131, 6,
          223, 147, 86, 246, 162, 71, 101, 24, 201, 117, 161, 225, 224, 11,
        ]),
        lockedSafeBase64:
          "MEwCAQEERzBFBAxXhXefAImJXnDjzqQEFmFkZGl0aW9uYWwgcHVibGljIGRhdGEEC+pMgYDDS+z1yk2nBBCDBt+TVvaiR2UYyXWh4eAL",
        keyBinary: Buffer.from([
          52, 123, 132, 93, 26, 102, 132, 189, 121, 140, 2, 16, 11, 244, 110,
          49, 97, 162, 254, 234, 84, 216, 200, 135, 72, 157, 88, 5, 168, 21,
          255, 7,
        ]),
        keyBase64: "NHuEXRpmhL15jAIQC/RuMWGi/upU2MiHSJ1YBagV/wc=",
      },
    },
  ],
]);
