import * as fs from "fs";
import FormData from "form-data";
import { spawn, execSync } from "child_process";
import { ArgumentParser } from "argparse";
import { ApiScanFormat, FormTypes, OnFailure, ScanMode, SubmitActions } from "./utils/enums";
import { exit } from "process";
import SOOSAnalysisApiClient from "@soos-io/api-client/dist/api/SOOSAnalysisApiClient";
import {
  getEnvVariable,
  isUrlAvailable,
  convertStringToBase64,
  sleep,
  obfuscateProperties,
  ensureEnumValue,
  ensureNonEmptyValue,
} from "@soos-io/api-client/dist/utilities";
import {
  ScanStatus,
  ScanType,
  soosLogger,
  LogLevel,
  OutputFormat,
  SOOS_CONSTANTS,
} from "@soos-io/api-client";
import { ZAPCommandGenerator, CONSTANTS } from "./utils";

export interface SOOSDASTAnalysisArgs {
  ajaxSpider: boolean;
  apiKey: string;
  apiScanFormat: ApiScanFormat;
  apiURL: string;
  appVersion: string;
  authDelayTime: number;
  authFormType: FormTypes;
  authLoginURL: string;
  authPassword: string;
  authPasswordField: string;
  authSecondSubmitField: string;
  authSubmitAction: SubmitActions;
  authSubmitField: string;
  authUsername: string;
  authUsernameField: string;
  authVerificationURL: string;
  bearerToken: string;
  branchName: string;
  branchURI: string;
  buildURI: string;
  buildVersion: string;
  checkoutDir: string;
  clientId: string;
  commitHash: string;
  contextFile: string;
  debug: boolean;
  disableRules: string;
  fullScanMinutes: number;
  integrationName: string;
  integrationType: string;
  logLevel: LogLevel;
  oauthParameters: string;
  oauthTokenUrl: string;
  onFailure: OnFailure;
  operatingEnvironment: string;
  otherOptions: string;
  outputFormat: OutputFormat;
  projectName: string;
  requestCookies: string;
  requestHeaders: string;
  scanMode: ScanMode;
  scriptVersion: string;
  targetURL: string;
  updateAddons: boolean;
  verbose: boolean;
}

class SOOSDASTAnalysis {
  constructor(private args: SOOSDASTAnalysisArgs) {}

  static parseArgs(): SOOSDASTAnalysisArgs {
    const parser = new ArgumentParser({ description: "SOOS DAST" });

    parser.add_argument("--ajaxSpider", {
      help: "Ajax Spider - Use the ajax spider in addition to the traditional one. Additional information: https://www.zaproxy.org/docs/desktop/addons/ajax-spider/.",
      action: "store_true",
      required: false,
    });

    parser.add_argument("--apiKey", {
      help: "SOOS API Key - get yours from https://app.soos.io/integrate/sca",
      default: getEnvVariable(CONSTANTS.SOOS.API_KEY_ENV_VAR),
      required: false,
    });

    parser.add_argument("--apiScanFormat", {
      help: "Target API format, OpenAPI, SOAP or GraphQL.",
      required: false,
      type: (value: string) => {
        return ensureEnumValue(ApiScanFormat, value);
      },
    });

    parser.add_argument("--apiURL", {
      help: "SOOS API URL - Intended for internal use only, do not modify.",
      default: "https://api.soos.io/api/",
      type: (value: string) => {
        return ensureNonEmptyValue(value, "apiURL");
      },
      required: false,
    });

    parser.add_argument("--appVersion", {
      help: "App Version - Intended for internal use only.",
      required: false,
    });

    parser.add_argument("--authDelayTime", {
      help: "Delay time in seconds to wait for the page to load after performing actions in the form. (Used only on authFormType: wait_for_password and multi_page)",
      default: CONSTANTS.AUTH.DELAY_TIME,
      required: false,
    });

    parser.add_argument("--authFormType", {
      help: `Form type of the login URL options are: simple (all fields are displayed at once),
             wait_for_password (Password field is displayed only after username is filled),
             or multi_page (Password field is displayed only after username is filled and submit is clicked).`,
      default: FormTypes.Simple,
      required: false,
      type: (value: string) => {
        return ensureEnumValue(FormTypes, value);
      },
    });

    parser.add_argument("--authLoginURL", {
      help: "Login URL to use when authentication is required.",
      required: false,
    });

    parser.add_argument("--authPassword", {
      help: "Password to use when authentication is required.",
      required: false,
    });

    parser.add_argument("--authPasswordField", {
      help: "Password input id to use when authentication is required.",
      required: false,
    });

    parser.add_argument("--authSecondSubmitField", {
      help: "Second submit button id to use when authentication is required.",
      required: false,
    });

    parser.add_argument("--authSubmitAction", {
      help: "Submit action to perform on form filled. Options: click or submit.",
      required: false,
      type: (value: string) => {
        return ensureEnumValue(SubmitActions, value);
      },
    });

    parser.add_argument("--authSubmitField", {
      help: "Submit button id to use when authentication is required.",
      required: false,
    });

    parser.add_argument("--authUsername", {
      help: "Username to use when authentication is required.",
      required: false,
    });

    parser.add_argument("--authUsernameField", {
      help: "Username input id to use when authentication is required.",
      required: false,
    });

    parser.add_argument("--authVerificationURL", {
      help: "URL used to verify authentication success, should be an URL that is expected to throw 200/302 during any authFormType authentication. If authentication fails when this URL is provided, the scan will be terminated.",
      required: false,
    });

    parser.add_argument("--bearerToken", {
      help: "Bearer token, adds a Authentication header with the token value.",
      required: false,
    });

    parser.add_argument("--branchName", {
      help: "The name of the branch from the SCM System.",
      default: null,
      required: false,
    });

    parser.add_argument("--branchURI", {
      help: "The URI to the branch from the SCM System.",
      default: null,
      required: false,
    });

    parser.add_argument("--buildURI", {
      help: "URI to CI build info.",
      default: null,
      required: false,
    });

    parser.add_argument("--buildVersion", {
      help: "Version of application build artifacts.",
      default: null,
      required: false,
    });

    parser.add_argument("--checkoutDir", {
      help: "Directory where the SARIF file will be created, used by Github Actions.",
      required: false,
      nargs: "*",
    });

    parser.add_argument("--clientId", {
      help: "SOOS Client ID - get yours from https://app.soos.io/integrate/sca",
      default: getEnvVariable(CONSTANTS.SOOS.CLIENT_ID_ENV_VAR),
      required: false,
    });

    parser.add_argument("--commitHash", {
      help: "The commit hash value from the SCM System.",
      default: null,
      required: false,
    });

    parser.add_argument("--contextFile", {
      help: "Context file which will be loaded prior to scanning the target.",
      nargs: "*",
      required: false,
    });

    parser.add_argument("--debug", {
      help: "Enable debug logging for ZAP.",
      action: "store_true",
      required: false,
    });

    parser.add_argument("--disableRules", {
      help: "Comma separated list of ZAP rules IDs to disable. List for reference https://www.zaproxy.org/docs/alerts/",
      required: false,
      nargs: "*",
    });

    parser.add_argument("--fullScanMinutes", {
      help: "Number of minutes for the spider to run.",
      required: false,
    });

    parser.add_argument("--integrationName", {
      help: "Integration Name - Intended for internal use only.",
      required: false,
    });

    parser.add_argument("--integrationType", {
      help: "Integration Type - Intended for internal use only.",
      required: false,
      default: CONSTANTS.SOOS.DEFAULT_INTEGRATION_TYPE,
    });

    parser.add_argument("--logLevel", {
      help: "Minimum level to show logs: PASS, IGNORE, INFO, WARN, FAIL, DEBUG, ERROR.",
      default: LogLevel.INFO,
      required: false,
      type: (value: string) => {
        return ensureEnumValue(LogLevel, value);
      },
    });

    parser.add_argument("--oauthParameters", {
      help: `Parameters to be added to the oauth token request. (eg --oauthParameters="client_id:clientID, client_secret:clientSecret, grant_type:client_credentials").`,
      required: false,
      nargs: "*",
    });

    parser.add_argument("--oauthTokenUrl", {
      help: "The authentication URL that grants the access_token.",
      required: false,
    });

    parser.add_argument("--onFailure", {
      help: "Action to perform when the scan fails. Options: fail_the_build, continue_on_failure.",
      default: OnFailure.Continue,
      required: false,
      type: (value: string) => {
        return ensureEnumValue(OnFailure, value);
      },
    });

    parser.add_argument("--operatingEnvironment", {
      help: "Set Operating environment for information purposes only.",
      default: null,
      required: false,
    });

    parser.add_argument("--otherOptions", {
      help: "Other command line arguments sent directly to the script for items not supported by other command line arguments",
      required: false,
      nargs: "*",
    });

    parser.add_argument("--outputFormat", {
      help: "Output format for vulnerabilities: only the value SARIF is available at the moment",
      required: false,
      type: (value: string) => {
        return ensureEnumValue(OutputFormat, value);
      },
    });

    parser.add_argument("--projectName", {
      help: "Project Name - this is what will be displayed in the SOOS app.",
      required: true,
      type: (value: string) => {
        return ensureNonEmptyValue(value, "projectName");
      },
    });

    parser.add_argument("--requestCookies", {
      help: "Set Cookie values for the requests to the target URL",
      nargs: "*",
      required: false,
    });

    parser.add_argument("--requestHeaders", {
      help: "Set extra headers for the requests to the target URL",
      nargs: "*",
      required: false,
    });

    parser.add_argument("--scanMode", {
      help: "Scan Mode - Available modes: baseline, fullscan, and apiscan (for more information about scan modes visit https://github.com/soos-io/soos-dast#scan-modes)",
      default: ScanMode.Baseline,
      required: false,
      type: (value: string) => {
        return ensureEnumValue(ScanMode, value);
      },
    });

    parser.add_argument("--scriptVersion", {
      help: "Script Version - Intended for internal use only.",
      required: false,
    });

    parser.add_argument("--updateAddons", {
      help: "Update ZAP Addons - Update ZAP Addons before running the scan.",
      action: "store_true",
    });

    parser.add_argument("--verbose", {
      help: "Enable verbose logging.",
      action: "store_true",
      required: false,
    });

    parser.add_argument("targetURL", {
      help: "Target URL - URL of the site or api to scan. The URL should include the protocol. Ex: https://www.example.com",
    });

    soosLogger.info("Parsing arguments");
    return parser.parse_args();
  }

  async runAnalysis(): Promise<void> {
    let scanDone: boolean = false;
    let projectHash: string | undefined;
    let branchHash: string | undefined;
    let analysisId: string | undefined;
    const soosApiClient = new SOOSAnalysisApiClient(this.args.apiKey, this.args.apiURL);
    try {
      soosLogger.info(`Project Name: ${this.args.projectName}`);
      soosLogger.info(`Scan Mode: ${this.args.scanMode}`);
      soosLogger.info(`API URL: ${this.args.apiURL}`);
      soosLogger.info(`Target URL: ${this.args.targetURL}`);
      soosLogger.logLineSeparator();

      soosLogger.info(`Checking if url '${this.args.targetURL}' is available...`);
      if (this.args.scanMode !== ScanMode.ApiScan) {
        const urlAvailable = await isUrlAvailable(this.args.targetURL);
        if (!urlAvailable) {
          soosLogger.error(`The URL ${this.args.targetURL} is not available.`);
          exit(1);
        }
      }

      soosLogger.info(`Creating scan for project ${this.args.projectName}...`);
      const result = await soosApiClient.createScan({
        clientId: this.args.clientId,
        projectName: this.args.projectName,
        commitHash: this.args.commitHash,
        branch: this.args.branchName,
        buildVersion: this.args.buildVersion,
        buildUri: this.args.buildURI,
        branchUri: this.args.branchURI,
        integrationType: this.args.integrationType,
        operatingEnvironment: this.args.operatingEnvironment,
        integrationName: this.args.integrationName,
        appVersion: this.args.appVersion,
        scriptVersion: null,
        contributingDeveloperAudit: undefined,
        scanType: ScanType.DAST,
        toolName: CONSTANTS.DAST.TOOL,
        toolVersion: CONSTANTS.DAST.TOOL_VERSION,
      });
      projectHash = result.projectHash;
      branchHash = result.branchHash;
      analysisId = result.analysisId;

      execSync("mkdir -p ~/.ZAP/reports /root/.ZAP/reports");

      execSync("cp -R /zap/reports/traditional-json-headers ~/.ZAP/reports/traditional-json");
      execSync("cp -R /zap/reports/traditional-json-headers /root/.ZAP/reports/traditional-json");

      const zapCommandGenerator = new ZAPCommandGenerator(this.args);
      soosLogger.info(`Generating ZAP command... ${this.args.scanMode}`);
      const command = zapCommandGenerator.runCommandGeneration(this.args.scanMode);
      soosLogger.info(`Running command: ${command}`);
      await SOOSDASTAnalysis.runZap(command);
      const runSuccess = fs.existsSync(CONSTANTS.FILES.REPORT_SCAN_RESULT_FILE);
      soosLogger.info(`Scan finished with success: ${runSuccess}`);

      const discoveredUrls =
        fs.existsSync(CONSTANTS.FILES.SPIDERED_URLS_FILE_PATH) &&
        fs.statSync(CONSTANTS.FILES.SPIDERED_URLS_FILE_PATH).isFile()
          ? fs
              .readFileSync(CONSTANTS.FILES.SPIDERED_URLS_FILE_PATH, "utf-8")
              .split("\n")
              .filter((url) => url.trim() !== "")
          : [];

      const data = JSON.parse(fs.readFileSync(CONSTANTS.FILES.REPORT_SCAN_RESULT_FILE, "utf-8"));
      data["discoveredUrls"] = discoveredUrls;
      fs.writeFileSync(CONSTANTS.FILES.REPORT_SCAN_RESULT_FILE, JSON.stringify(data, null, 4));
      const formData = new FormData();

      formData.append("resultVersion", data["@version"]);
      formData.append(
        "file",
        convertStringToBase64(
          JSON.stringify(
            JSON.parse(
              fs.readFileSync(
                CONSTANTS.FILES.REPORT_SCAN_RESULT_FILE,
                SOOS_CONSTANTS.FileUploads.Encoding
              )
            )
          )
        ),
        "base64Manifest"
      );
      soosLogger.logLineSeparator();
      soosLogger.info(`Starting report results processing`);
      soosLogger.info(`Uploading scan result for project ${this.args.projectName}...`);
      await soosApiClient.uploadScanToolResult({
        clientId: this.args.clientId,
        projectHash,
        branchHash,
        scanType: ScanType.DAST,
        scanId: analysisId,
        resultFile: formData,
      });
      soosLogger.info(`Scan result uploaded successfully`);

      scanDone = true;

      if (this.args.outputFormat !== undefined) {
        soosLogger.info(`Generating SARIF report  ${this.args.projectName}...`);
        const output = await soosApiClient.getFormattedScanResult({
          clientId: this.args.clientId,
          projectHash,
          branchHash,
          scanType: ScanType.DAST,
          scanId: analysisId,
          outputFormat: this.args.outputFormat,
        });
        if (output) {
          soosLogger.info(`Output ('${this.args.outputFormat}' format):`);
          soosLogger.info(JSON.stringify(output, null, 2));
          if (this.args.checkoutDir) {
            soosLogger.info(
              `Writing SARIF report to ${this.args.checkoutDir}/${CONSTANTS.FILES.SARIF}`
            );
            fs.writeFileSync(
              `${this.args.checkoutDir}/${CONSTANTS.FILES.SARIF}`,
              JSON.stringify(output, null, 2)
            );
          }
        }
      }

      if (this.args.onFailure === OnFailure.Fail) {
        await this.waitForScanToFinish({
          apiClient: soosApiClient,
          scanStatusUrl: result.scanStatusUrl,
          attempt: 0,
        });
      }

      soosLogger.logLineSeparator();
      soosLogger.info(`SOOS DAST Analysis finished successfully`);
      soosLogger.info(`Project URL: ${result.scanUrl}`);
    } catch (error) {
      soosLogger.error(error);
      if (projectHash && branchHash && analysisId && !scanDone)
        await soosApiClient.updateScanStatus({
          clientId: this.args.clientId,
          projectHash,
          branchHash,
          scanType: ScanType.DAST,
          scanId: analysisId,
          status: ScanStatus.Error,
          message: `Error while performing scan.`,
        });
      soosLogger.error("There was an error while performing the scan. Exiting script.");
      exit(1);
    }
  }

  async waitForScanToFinish({
    apiClient,
    scanStatusUrl,
    attempt,
  }: {
    apiClient: SOOSAnalysisApiClient;
    scanStatusUrl: string;
    attempt: number;
  }): Promise<void> {
    const status = await apiClient.getScanStatus({ scanStatusUrl });

    if (!status.isComplete) {
      soosLogger.info(`Scan status: ${status.status}...`);
      if (attempt >= CONSTANTS.STATUS.MAX_ATTEMPTS) {
        soosLogger.error("Max attempts reached fetching scan status.");
        soosLogger.error("Failing the build.");
        process.exit(1);
      }
      await sleep(CONSTANTS.STATUS.DELAY_TIME);
      return this.waitForScanToFinish({ apiClient, scanStatusUrl, attempt: attempt++ });
    }

    if (status.status === ScanStatus.FailedWithIssues) {
      soosLogger.info("Analysis complete - Failures reported");
      soosLogger.info("Failing the build.");
      process.exit(1);
    } else if (status.status === ScanStatus.Incomplete) {
      soosLogger.info(
        "Analysis Incomplete. It may have been cancelled or superseded by another scan."
      );
      soosLogger.info("Failing the build.");
      process.exit(1);
    } else if (status.status === ScanStatus.Error) {
      soosLogger.info("Analysis Error.");
      soosLogger.info("Failing the build.");
      process.exit(1);
    } else if (scanStatusUrl === "finished") {
      return;
    } else {
      process.exit(0);
    }
  }

  static async runZap(command: string): Promise<void> {
    return new Promise((resolve, reject) => {
      soosLogger.logLineSeparator();
      soosLogger.info("Running ZAP");
      const zapProcess = spawn(command, {
        shell: true,
        stdio: "inherit",
      });

      zapProcess.on("close", (code) => {
        if (code === 0 || code === 2) {
          resolve();
        } else {
          reject(`ZAP Process: child process exited with code ${code}`);
        }
      });
    });
  }

  static async createAndRun(): Promise<void> {
    soosLogger.info("Starting SOOS DAST Analysis");
    soosLogger.logLineSeparator();
    try {
      const args = this.parseArgs();
      soosLogger.setMinLogLevel(args.logLevel);
      soosLogger.setVerbose(args.verbose);
      soosLogger.info("Configuration read");
      soosLogger.verboseDebug(
        JSON.stringify(
          obfuscateProperties(args as unknown as Record<string, unknown>, [
            "apiKey",
            "authPassword",
            "bearerToken",
          ]),
          null,
          2
        )
      );
      ensureNonEmptyValue(args.clientId, "clientId");
      ensureNonEmptyValue(args.apiKey, "apiKey");
      soosLogger.logLineSeparator();
      const soosDASTAnalysis = new SOOSDASTAnalysis(args);
      await soosDASTAnalysis.runAnalysis();
    } catch (error) {
      soosLogger.error(`Error on createAndRun: ${error}`);
      exit(1);
    }
  }
}

SOOSDASTAnalysis.createAndRun();
