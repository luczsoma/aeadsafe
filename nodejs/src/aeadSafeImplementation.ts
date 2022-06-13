export abstract class AeadSafeImplementation {
  public abstract lockSafe(
    plainText: Buffer,
    associatedData: Buffer
  ): { unwrappedLockedSafe: Buffer; key: Buffer };
  public abstract unlockSafe(
    unwrappedLockedSafe: Buffer,
    key: Buffer
  ): { plainText: Buffer; associatedData: Buffer };
}
