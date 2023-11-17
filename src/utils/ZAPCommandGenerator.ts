import { SOOSDASTAnalysisArgs } from "..";
import { CONSTANTS } from "./constants";
import { ScanMode } from "./enums";

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
    this.addEnvironmentVariable("OAUTH_PARAMETERS", this.config.oauthParameters);
    this.addEnvironmentVariable("OAUTH_TOKEN_URL", this.config.oauthTokenUrl);
  }

  private generateCommand(args: string[]): string {
    this.addOption(args, CONSTANTS.ZAP.AJAX_SPIDER_OPTION, this.config.ajaxSpider);
    this.addOption(args, CONSTANTS.ZAP.CONTEXT_FILE_OPTION, this.config.contextFile);
    this.addOption(args, CONSTANTS.ZAP.DEBUG_OPTION, this.config.debug);
    this.addOption(args, CONSTANTS.ZAP.HOOK_OPTION, CONSTANTS.FILES.ZAP_CUSTOM_HOOK_SCRIPT);
    this.addOption(
      args,
      CONSTANTS.ZAP.JSON_REPORT_OPTION,
      CONSTANTS.FILES.REPORT_SCAN_RESULT_FILENAME
    );

    this.addOption(args, CONSTANTS.ZAP.SPIDER_MINUTES_OPTION, this.config.fullScanMinutes);
    this.addOption(args, CONSTANTS.ZAP.TARGET_URL_OPTION, this.config.targetURL);
    this.addHookParams();

    if (this.config.otherOptions) {
      args.push(this.config.otherOptions);
    }

    if (this.config.updateAddons) {
      args.push(CONSTANTS.ZAP.UPDATE_ADDONS_OPTION);
    }

    return args.join(" ");
  }

  private baselineScan(): string {
    const args = [CONSTANTS.ZAP.COMMAND, CONSTANTS.ZAP.SCRIPTS.BASE_LINE];
    return this.generateCommand(args);
  }

  private fullScan(): string {
    const args = [CONSTANTS.ZAP.COMMAND, CONSTANTS.ZAP.SCRIPTS.FULL_SCAN];
    this.addOption(args, CONSTANTS.ZAP.TARGET_URL_OPTION, this.config.targetURL);
    return this.generateCommand(args);
  }

  private apiScan(): string {
    const args = [CONSTANTS.ZAP.COMMAND, CONSTANTS.ZAP.SCRIPTS.API_SCAN];
    this.addOption(args, CONSTANTS.ZAP.TARGET_URL_OPTION, this.config.targetURL);
    this.addOption(args, CONSTANTS.ZAP.FORMAT_OPTION, this.config.apiScanFormat);
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
