import { SOOSDASTAnalysisArgs } from "..";
import { SOOS_DAST_CONSTANTS } from "../constants";
import { ScanMode } from "../enums";

const SOOS_ZAP_CONSTANTS = {
  PythonBin: "python3",
  Options: {
    AjaxSpider: "-j",
    ContextFile: "-n",
    Debug: "-d",
    Format: "-f",
    Hook: "--hook",
    JsonReport: "-J",
    SpiderMinutes: "-m",
    TargetUrl: "-t",
    UpdateAddons: "--updateAddons",
  },
  Scripts: {
    ApiScan: "/zap/zap-api-scan.py",
    Baseline: "/zap/zap-baseline.py",
    FullScan: "/zap/zap-full-scan.py",
  },
};

export class ZAPCommandGenerator {
  constructor(private config: SOOSDASTAnalysisArgs) {}

  private addOption(args: string[], option: string, value?: string | number | boolean) {
    if (value) {
      args.push(option);
      if (typeof value !== "boolean") args.push(value.toString());
    }
  }

  private addEnvironmentVariable(name: string, value: any) {
    if (value !== undefined) {
      process.env[name] = String(value);
    }
  }

  private addHookParams() {
    this.addEnvironmentVariable("AUTH_ACTION", this.config.authSubmitAction);
    this.addEnvironmentVariable("AUTH_BEARER_TOKEN", this.config.bearerToken);
    this.addEnvironmentVariable("AUTH_DELAY_TIME", this.config.authDelayTime);
    this.addEnvironmentVariable("AUTH_FORM_TYPE", this.config.authFormType);
    this.addEnvironmentVariable("AUTH_LOGIN_URL", this.config.authLoginURL);
    this.addEnvironmentVariable("AUTH_PASSWORD", this.config.authPassword);
    this.addEnvironmentVariable("AUTH_PASSWORD_FIELD", this.config.authPasswordField);
    this.addEnvironmentVariable("AUTH_SECOND_SUBMIT_FIELD", this.config.authSecondSubmitField);
    this.addEnvironmentVariable("AUTH_SUBMIT_ACTION", this.config.authSubmitAction);
    this.addEnvironmentVariable("AUTH_SUBMIT_FIELD", this.config.authSubmitField);
    this.addEnvironmentVariable("AUTH_USERNAME", this.config.authUsername);
    this.addEnvironmentVariable("AUTH_USERNAME_FIELD", this.config.authUsernameField);
    this.addEnvironmentVariable("AUTH_VERIFICATION_URL", this.config.authVerificationURL);
    this.addEnvironmentVariable("CUSTOM_COOKIES", this.config.requestCookies);
    this.addEnvironmentVariable("CUSTOM_HEADER", this.config.requestHeaders);
    this.addEnvironmentVariable("DISABLE_RULES", this.config.disableRules);
    this.addEnvironmentVariable("EXCLUDE_URLS_FILE", this.config.excludeUrlsFile);
    this.addEnvironmentVariable("INCLUDE_URLS_FILE", this.config.includeUrlsFile);
    this.addEnvironmentVariable("OAUTH_PARAMETERS", this.config.oauthParameters);
    this.addEnvironmentVariable("OAUTH_TOKEN_URL", this.config.oauthTokenUrl);
    if (this.config.debug) this.addEnvironmentVariable("DEBUG_MODE", this.config.debug);
  }

  private generateCommand(args: string[]): string {
    this.addOption(args, SOOS_ZAP_CONSTANTS.Options.AjaxSpider, this.config.ajaxSpider);
    this.addOption(args, SOOS_ZAP_CONSTANTS.Options.ContextFile, this.config.contextFile);
    this.addOption(args, SOOS_ZAP_CONSTANTS.Options.Debug, this.config.debug);
    this.addOption(args, SOOS_ZAP_CONSTANTS.Options.Hook, SOOS_DAST_CONSTANTS.Files.ZapHookFile);
    this.addOption(
      args,
      SOOS_ZAP_CONSTANTS.Options.JsonReport,
      SOOS_DAST_CONSTANTS.Files.ReportScanResultFilename,
    );

    this.addOption(args, SOOS_ZAP_CONSTANTS.Options.SpiderMinutes, this.config.fullScanMinutes);
    this.addOption(args, SOOS_ZAP_CONSTANTS.Options.TargetUrl, this.config.targetURL);
    this.addHookParams();

    if (this.config.otherOptions) {
      args.push(this.config.otherOptions);
    }

    if (this.config.updateAddons) {
      args.push(SOOS_ZAP_CONSTANTS.Options.UpdateAddons);
    }

    return args.join(" ");
  }

  private baselineScan(): string {
    const args = [SOOS_ZAP_CONSTANTS.PythonBin, SOOS_ZAP_CONSTANTS.Scripts.Baseline];
    return this.generateCommand(args);
  }

  private fullScan(): string {
    const args = [SOOS_ZAP_CONSTANTS.PythonBin, SOOS_ZAP_CONSTANTS.Scripts.FullScan];
    this.addOption(args, SOOS_ZAP_CONSTANTS.Options.TargetUrl, this.config.targetURL);
    return this.generateCommand(args);
  }

  private apiScan(): string {
    const args = [SOOS_ZAP_CONSTANTS.PythonBin, SOOS_ZAP_CONSTANTS.Scripts.ApiScan];
    this.addOption(args, SOOS_ZAP_CONSTANTS.Options.TargetUrl, this.config.targetURL);
    this.addOption(args, SOOS_ZAP_CONSTANTS.Options.Format, this.config.apiScanFormat);
    return this.generateCommand(args);
  }

  public runCommandGeneration(mode: ScanMode): string {
    switch (mode) {
      case ScanMode.Baseline:
        return this.baselineScan();
      case ScanMode.FullScan:
        return this.fullScan();
      case ScanMode.ApiScan:
        return this.apiScan();
    }
  }
}
