export interface LockSafeResult<
  ResultType extends Buffer | string,
  KeyType extends Buffer | string
> {
  lockedSafe: ResultType;
  key: KeyType;
}
