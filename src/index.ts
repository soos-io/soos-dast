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
  convertStringToB64,
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
  apiKey: string;
  apiURL: string;
  appVersion: string;
  branchName: string;
  branchUri: string;
  buildUri: string;
  buildVersion: string;
  clientId: string;
  commitHash: string;
  integrationName: string;
  integrationType: string;
  logLevel: LogLevel;
  onFailure: OnFailure;
  operatingEnvironment: string;
  projectName: string;
  scriptVersion: string;
  targetURL: string;
  scanMode: ScanMode;
  debug: boolean;
  ajaxSpider: boolean;
  contextFile: string;
  fullScanMinutes: number;
  apiScanFormat: ApiScanFormat;
  authUsername: string;
  authPassword: string;
  authLoginURL: string;
  authUsernameField: string;
  authPasswordField: string;
  authSubmitField: string;
  authSecondSubmitField: string;
  authSubmitAction: SubmitActions;
  authFormType: FormTypes;
  authDelayTime: number;
  authVerificationURL: string;
  requestCookies: string;
  requestHeaders: string;
  reportRequestHeaders: boolean;
  bearerToken: string;
  oauthTokenUrl: string;
  oauthParameters: string;
  updateAddons: boolean;
  disableRules: string;
  otherOptions: string;
  verbose: boolean;
  outputFormat: OutputFormat;
  checkoutDir: string;
}
class SOOSDASTAnalysis {
  constructor(private args: SOOSDASTAnalysisArgs) {}

  static parseArgs(): SOOSDASTAnalysisArgs {
    const parser = new ArgumentParser({ description: "SOOS DAST" });

    parser.add_argument("targetURL", {
      help: "Target URL - URL of the site or api to scan. The URL should include the protocol. Ex: https://www.example.com",
    });

    parser.add_argument("--clientId", {
      help: "SOOS Client ID - get yours from https://app.soos.io/integrate/sca",
      default: getEnvVariable(CONSTANTS.SOOS.CLIENT_ID_ENV_VAR),
      required: false,
    });

    parser.add_argument("--apiKey", {
      help: "SOOS API Key - get yours from https://app.soos.io/integrate/sca",
      default: getEnvVariable(CONSTANTS.SOOS.API_KEY_ENV_VAR),
      required: false,
    });

    parser.add_argument("--projectName", {
      help: "Project Name - this is what will be displayed in the SOOS app.",
      required: true,
    });

    parser.add_argument("--scanMode", {
      help: "Scan Mode - Available modes: baseline, fullscan, and apiscan (for more information about scan modes visit https://github.com/soos-io/soos-dast#scan-modes)",
      default: ScanMode.Baseline,
      required: false,
      type: (value: string) => {
        if (Object.values(ScanMode).includes(value as ScanMode)) {
          return value as ScanMode;
        } else {
          throw new Error(`Invalid scan mode: ${value}`);
        }
      },
    });

    parser.add_argument("--debug", {
      help: "Enable debug logging for zap.",
      action: "store_true",
      required: false,
    });

    parser.add_argument("--ajaxSpider", {
      help: "Enable Ajax Spider.",
      action: "store_true",
      required: false,
    });

    parser.add_argument("--contextFile", {
      help: "Context file which will be loaded prior to scanning the target.",
      nargs: "*",
      required: false,
    });

    parser.add_argument("--fullScanMinutes", {
      help: "Number of minutes for the spider to run.",
      default: 120,
      required: false,
    });

    parser.add_argument("--apiScanFormat", {
      help: "Target API format, OpenAPI, SOAP or GraphQL.",
      required: false,
      type: (value: string) => {
        if (Object.values(ApiScanFormat).includes(value as ApiScanFormat)) {
          return value as ApiScanFormat;
        } else {
          throw new Error(`Invalid Api Scan Format: ${value}`);
        }
      },
    });

    parser.add_argument("--authUsername", {
      help: "Username to use in auth apps.",
      required: false,
    });

    parser.add_argument("--authPassword", {
      help: "Password to use in auth apps.",
      required: false,
    });

    parser.add_argument("--authLoginURL", {
      help: "Login URL to use in auth apps.",
      required: false,
    });

    parser.add_argument("--authUsernameField", {
      help: "Username input id to use in auth apps.",
      required: false,
    });

    parser.add_argument("--authPasswordField", {
      help: "Password input id to use in auth apps.",
      required: false,
    });

    parser.add_argument("--authSubmitField", {
      help: "Submit button id to use in auth apps.",
      required: false,
    });

    parser.add_argument("--authSecondSubmitField", {
      help: "Second submit button id to use in auth apps.",
      required: false,
    });

    parser.add_argument("--authSubmitAction", {
      help: "Submit action to perform on form filled. Options: click or submit.",
      required: false,
      type: (value: string) => {
        if (Object.values(SubmitActions).includes(value as SubmitActions)) {
          return value as SubmitActions;
        } else {
          throw new Error(`Invalid submit action: ${value}`);
        }
      },
    });

    parser.add_argument("--authFormType", {
      help: `Form type of the login URL options are: simple (all fields are displayed at once),
             wait_for_password (Password field is displayed only after username is filled),
             or multi_page (Password field is displayed only after username is filled and submit is clicked).`,
      default: FormTypes.Simple,
      required: false,
      type: (value: string) => {
        if (Object.values(FormTypes).includes(value as FormTypes)) {
          return value as FormTypes;
        } else {
          throw new Error(`Invalid submit action: ${value}`);
        }
      },
    });

    parser.add_argument("--authVerificationURL", {
      help: "URL used to verify authentication success. If authentication fails when this URL is provided, the scan will be terminated.",
      required: false,
    });

    parser.add_argument("--authDelayTime", {
      help: "Delay time in seconds to wait for the page to load after performing actions in the form. (Used only on authFormType: wait_for_password and multi_page)",
      default: CONSTANTS.AUTH.DELAY_TIME,
      required: false,
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

    parser.add_argument("--onFailure", {
      help: "Action to perform when the scan fails. Options: fail_the_build, continue_on_failure.",
      default: OnFailure.Continue,
      required: false,
      type: (value: string) => {
        if (Object.values(OnFailure).includes(value as OnFailure)) {
          return value as OnFailure;
        } else {
          throw new Error(`Invalid submit action: ${value}`);
        }
      },
    });

    parser.add_argument("--outputFormat", {
      help: "Output format for vulnerabilities: only the value SARIF is available at the moment",
      required: false,
      type: (value: string) => {
        if (value in OutputFormat) {
          return OutputFormat[value as keyof typeof OutputFormat];
        } else {
          throw new Error(`Invalid output format: ${value}`);
        }
      },
    });

    parser.add_argument("--checkoutDir", {
      help: "Directory where the SARIF file will be created, used by Github Actions.",
      required: false,
      nargs: "*",
    });

    parser.add_argument("--reportRequestHeaders", {
      help: "Include request/response headers data in report.",
      default: true,
      required: false,
    });

    parser.add_argument("--bearerToken", {
      help: "Bearer token, adds a Authentication header with the token value.",
      required: false,
    });

    parser.add_argument("--oauthTokenUrl", {
      help: "The authentication URL to use to obtain an OAuth token.",
      required: false,
    });

    parser.add_argument("--oauthParameters", {
      help: 'Parameters to be added to the oauth token request. (eg --oauthParameters="client_id:clientID, client_secret:clientSecret, grant_type:client_credentials")',
      required: false,
      nargs: "*",
    });

    parser.add_argument("--updateAddons", {
      help: "Internal use only. Update ZAP addons.",
      action: "store_true",
      required: false,
    });

    parser.add_argument("--disableRules", {
      help: "Comma separated list of ZAP rules IDs to disable. List for reference https://www.zaproxy.org/docs/alerts/",
      required: false,
      nargs: "*",
    });

    parser.add_argument("--otherOptions", {
      help: "Other Options to pass to zap.",
      required: false,
    });

    parser.add_argument("--apiURL", {
      help: "SOOS API URL - Intended for internal use only, do not modify.",
      default: "https://api.soos.io/api/",
      required: false,
    });

    parser.add_argument("--logLevel", {
      help: "Minimum level to show logs: PASS, IGNORE, INFO, WARN or FAIL.",
      default: LogLevel.INFO,
      required: false,
      type: (value: string) => {
        if (value in LogLevel) {
          return LogLevel[value as keyof typeof LogLevel];
        } else {
          throw new Error(`Invalid log level: ${value}`);
        }
      },
    });

    parser.add_argument("--integrationName", {
      help: "Integration Name - Intended for internal use only.",
      required: false,
    });

    parser.add_argument("--integrationType", {
      help: "Integration Type - Intended for internal use only.",
      required: false,
    });

    parser.add_argument("--scriptVersion", {
      help: "Script Version - Intended for internal use only.",
      required: false,
    });

    parser.add_argument("--appVersion", {
      help: "App Version - Intended for internal use only.",
      required: false,
    });

    parser.add_argument("--commitHash", {
      help: "The commit hash value from the SCM System.",
      default: null,
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

    parser.add_argument("--buildVersion", {
      help: "Version of application build artifacts.",
      default: null,
      required: false,
    });

    parser.add_argument("--buildURI", {
      help: "URI to CI build info.",
      default: null,
      required: false,
    });

    parser.add_argument("--operatingEnvironment", {
      help: "Set Operating environment for information purposes only.",
      default: null,
      required: false,
    });

    parser.add_argument("--verbose", {
      help: "Enable verbose logging.",
      action: "store_true",
      required: false,
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
      soosLogger.info("Starting SOOS DAST Analysis");
      soosLogger.info(`Creating scan for project ${this.args.projectName}...`);
      const result = await soosApiClient.createScan({
        clientId: this.args.clientId,
        projectName: this.args.projectName,
        commitHash: this.args.commitHash,
        branch: this.args.branchName,
        buildVersion: this.args.buildVersion,
        buildUri: this.args.buildUri,
        branchUri: this.args.branchUri,
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

      soosLogger.info(`Checking if url '${this.args.targetURL}' is available...`);
      if (!(await isUrlAvailable(this.args.targetURL))) {
        soosLogger.error(`The URL ${this.args.targetURL} is not available.`);
        exit(1);
      }

      execSync("mkdir -p ~/.ZAP/reports /root/.ZAP/reports");

      if (this.args.reportRequestHeaders) {
        execSync("cp -R /zap/reports/traditional-json-headers ~/.ZAP/reports/traditional-json");
        execSync("cp -R /zap/reports/traditional-json-headers /root/.ZAP/reports/traditional-json");
      } else {
        execSync("cp -R /zap/reports/traditional-json ~/.ZAP/reports/traditional-json");
        execSync("cp -R /zap/reports/traditional-json /root/.ZAP/reports/traditional-json");
      }

      const zapCommandGenerator = new ZAPCommandGenerator(this.args);
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
        convertStringToB64(
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
      soosLogger.info(`Uploading scan result for project ${this.args.projectName}...`);
      await soosApiClient.uploadScanToolResult({
        clientId: this.args.clientId,
        projectHash,
        branchHash,
        scanType: ScanType.DAST,
        scanId: analysisId,
        resultFile: formData,
      });

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

  static async runZap(command: string): Promise<void> {
    return new Promise((resolve, reject) => {
      console.log("Running ZAP");
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
    try {
      const args = this.parseArgs();
      soosLogger.setMinLogLevel(args.logLevel);
      soosLogger.setVerbose(args.verbose);
      const soosDASTAnalysis = new SOOSDASTAnalysis(args);
      await soosDASTAnalysis.runAnalysis();
    } catch (error) {
      soosLogger.error(`Error on createAndRun: ${error}`);
      exit(1);
    }
  }
}

SOOSDASTAnalysis.createAndRun();
