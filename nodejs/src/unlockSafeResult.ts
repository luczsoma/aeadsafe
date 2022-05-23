export interface UnlockSafeResult<ResultType extends Buffer | string> {
  secretData: ResultType;
  additionalPublicData: ResultType;
}
