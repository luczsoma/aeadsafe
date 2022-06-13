export const keyEncodings = ["binary", "base64"] as const;
export type KeyEncoding = typeof keyEncodings[number];
