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
