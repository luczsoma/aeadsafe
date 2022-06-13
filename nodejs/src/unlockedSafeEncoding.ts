export const unlockedSafeEncodings = ["binary", "string"] as const;
export type UnlockedSafeEncoding = typeof unlockedSafeEncodings[number];
