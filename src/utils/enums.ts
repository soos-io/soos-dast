export enum ScanMode {
  Baseline = "baseline",
  FullScan = "fullscan",
  ApiScan = "apiscan",
}

export enum ApiScanFormat {
  OpenAPI = "OpenAPI",
  SOAP = "SOAP",
  GraphQL = "GraphQL",
}

export enum LogLevel {
  PASS = 0,
  IGNORE = 1,
  INFO = 2,
  WARN = 3,
  FAIL = 4,
  DEBUG = 5,
  ERROR = 6,
}

export enum OutputFormat {
  SARIF = "SARIF",
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

export enum OnFailure {
  Continue = "continue_on_failure",
  Fail = "fail_the_build",
}

export const ScanModeScripts: Record<ScanMode, string> = {
  [ScanMode.Baseline]: "/zap/zap-baseline.py",
  [ScanMode.FullScan]: "/zap/zap-full-scan.py",
  [ScanMode.ApiScan]: "/zap/zap-api-scan.py",
};
