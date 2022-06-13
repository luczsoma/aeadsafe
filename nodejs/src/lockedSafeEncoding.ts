export const lockedSafeEncodings = ["binary", "base64"] as const;
export type LockedSafeEncoding = typeof lockedSafeEncodings[number];
