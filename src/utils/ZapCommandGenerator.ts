import { SOOSDASTAnalysisArgs } from "..";
import {
  API_SCAN_SCRIPT,
  BASE_LINE_SCRIPT,
  FULL_SCAN_SCRIPT,
  PY_CMD,
  REPORT_SCAN_RESULT_FILENAME,
  ZAP_AJAX_SPIDER_OPTION,
  ZAP_CONTEXT_FILE_OPTION,
  ZAP_CUSTOM_HOOK_SCRIPT,
  ZAP_DEBUG_OPTION,
  ZAP_FORMAT_OPTION,
  ZAP_HOOK_OPTION,
  ZAP_JSON_REPORT_OPTION,
  ZAP_OPTIONS,
  ZAP_SPIDER_MINUTES_OPTION,
  ZAP_TARGET_URL_OPTION,
} from "./constants";
import { ScanMode } from "./enums";

export class ZapCommandGenerator {
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
    this.addEnvironmentVariable("AUTH_LOGIN_URL", this.config.authLoginURL);
    this.addEnvironmentVariable("AUTH_USERNAME", this.config.authUsername);
    this.addEnvironmentVariable("AUTH_PASSWORD", this.config.authPassword);
    this.addEnvironmentVariable("CUSTOM_COOKIES", this.config.requestCookies);
    this.addEnvironmentVariable("CUSTOM_HEADER", this.config.requestHeaders);
    this.addEnvironmentVariable("AUTH_BEARER_TOKEN", this.config.bearerToken);
    this.addEnvironmentVariable("AUTH_SUBMIT_FIELD", this.config.authSubmitField);
    this.addEnvironmentVariable("AUTH_SECOND_SUBMIT_FIELD", this.config.authSecondSubmitField);
    this.addEnvironmentVariable("AUTH_SUBMIT_ACTION", this.config.authSubmitAction);
    this.addEnvironmentVariable("AUTH_FORM_TYPE", this.config.authFormType);
    this.addEnvironmentVariable("AUTH_DELAY_TIME", this.config.authDelayTime);
    this.addEnvironmentVariable("AUTH_VERIFICATION_URL", this.config.authVerificationURL);
    this.addEnvironmentVariable("AUTH_USERNAME_FIELD", this.config.authUsernameField);
    this.addEnvironmentVariable("AUTH_PASSWORD_FIELD", this.config.authPasswordField);
    this.addEnvironmentVariable("OAUTH_TOKEN_URL", this.config.oauthTokenUrl);
    this.addEnvironmentVariable("OAUTH_PARAMETERS", this.config.oauthParameters);
    this.addEnvironmentVariable("DISABLE_RULES", this.config.disableRules);
  }

  private generateCommand(args: string[]): string {
    this.addOption(args, ZAP_TARGET_URL_OPTION, this.config.targetURL);
    this.addOption(args, ZAP_CONTEXT_FILE_OPTION, this.config.contextFile);
    this.addOption(args, ZAP_DEBUG_OPTION, this.config.debug);
    this.addOption(args, ZAP_AJAX_SPIDER_OPTION, this.config.ajaxSpider);
    this.addOption(args, ZAP_SPIDER_MINUTES_OPTION, this.config.fullScanMinutes);
    this.addOption(args, ZAP_JSON_REPORT_OPTION, REPORT_SCAN_RESULT_FILENAME);
    this.addOption(args, ZAP_OPTIONS, this.config.otherOptions);
    this.addOption(args, ZAP_HOOK_OPTION, ZAP_CUSTOM_HOOK_SCRIPT);
    this.addHookParams();

    return args.join(" ");
  }

  private baselineScan(): string {
    const args = [PY_CMD, BASE_LINE_SCRIPT];
    return this.generateCommand(args);
  }

  private fullScan(): string {
    const args = [PY_CMD, FULL_SCAN_SCRIPT];
    this.addOption(args, ZAP_TARGET_URL_OPTION, this.config.targetURL);
    return this.generateCommand(args);
  }

  private apiScan(): string {
    const args = [PY_CMD, API_SCAN_SCRIPT];
    this.addOption(args, ZAP_TARGET_URL_OPTION, this.config.targetURL);
    this.addOption(args, ZAP_FORMAT_OPTION, this.config.apiScanFormat);
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
