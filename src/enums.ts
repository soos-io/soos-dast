export enum ScanMode {
  Baseline = "baseline",
  FullScan = "fullscan",
  ApiScan = "apiscan",
}

export enum ApiScanFormat {
  OpenAPI = "openapi",
  SOAP = "soap",
  GraphQL = "graphql",
}

export enum SubmitActions {
  Submit = "submit",
  Click = "click",
}

export enum FormTypes {
  Simple = "simple",
  WaitForPassword = "wait_for_password",
  MultiPage = "multi_page",
}

export const ScanModeScripts: Record<ScanMode, string> = {
  [ScanMode.Baseline]: "/zap/zap-baseline.py",
  [ScanMode.FullScan]: "/zap/zap-full-scan.py",
  [ScanMode.ApiScan]: "/zap/zap-api-scan.py",
};
