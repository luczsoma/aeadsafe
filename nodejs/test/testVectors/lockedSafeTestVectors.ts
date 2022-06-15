import { LockedSafeTestVector } from "./lockedSafeTestVector.js";

export interface LockedSafeTestVectors {
  secretDataOnly: LockedSafeTestVector;
  additionalPublicDataOnly: LockedSafeTestVector;
  secretDataWithAdditionalPublicData: LockedSafeTestVector;
}
