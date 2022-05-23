export interface LockSafeResult<
  ResultType extends Buffer | string,
  KeyType extends Buffer | string
> {
  result: ResultType;
  key: KeyType;
}
