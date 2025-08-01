import { IDASTAnalysisArgs } from "..";
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
    Timeout: "-T",
  },
  Scripts: {
    ApiScan: "/zap/zap-api-scan.py",
    Baseline: "/zap/zap-baseline.py",
    FullScan: "/zap/zap-full-scan.py",
  },
};

export class ZAPCommandGenerator {
  constructor(private config: IDASTAnalysisArgs) {}

  private addOption(args: string[], option: string, value: string | number | boolean | undefined) {
    if (value) {
      args.push(option);
      if (typeof value !== "boolean") args.push(value.toString());
    }
  }

  private addEnvironmentVariable(name: string, value: string | number | boolean | undefined) {
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
    this.addEnvironmentVariable("CUSTOM_HEADER", this.config.requestHeaders);
    this.addEnvironmentVariable("DEBUG_MODE", this.config.debug);
    this.addEnvironmentVariable("DISABLE_RULES", this.config.disableRules);
    this.addEnvironmentVariable("EXCLUDE_URLS_FILE", this.config.excludeUrlsFile);
  }

  private createCommandline(args: string[]): string {
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
    this.addOption(args, SOOS_ZAP_CONSTANTS.Options.Timeout, this.config.timeout);
    this.addHookParams();

    if (this.config.otherOptions) {
      args.push(this.config.otherOptions);
    }

    return args.join(" ");
  }

  public createCommand(mode: ScanMode): string {
    const args = [SOOS_ZAP_CONSTANTS.PythonBin];

    switch (mode) {
      case ScanMode.ApiScan:
        args.push(SOOS_ZAP_CONSTANTS.Scripts.ApiScan);
        this.addOption(args, SOOS_ZAP_CONSTANTS.Options.Format, this.config.apiScanFormat);
        break;
      case ScanMode.Baseline:
        args.push(SOOS_ZAP_CONSTANTS.Scripts.Baseline);
        break;
      case ScanMode.FullScan:
        args.push(SOOS_ZAP_CONSTANTS.Scripts.FullScan);
        break;
    }

    return this.createCommandline(args);
  }
}
