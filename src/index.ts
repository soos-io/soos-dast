import * as fs from "fs";
import FormData from "form-data";
import { spawn } from "child_process";
import { ApiScanFormat, FormTypes, ScanMode, SubmitActions } from "./enums";
import { exit } from "process";
import {
  isUrlAvailable,
  convertStringToBase64,
  obfuscateProperties,
  getAnalysisExitCodeWithMessage,
} from "@soos-io/api-client/dist/utilities";
import {
  ScanStatus,
  ScanType,
  soosLogger,
  OutputFormat,
  SOOS_CONSTANTS,
  IntegrationName,
  IntegrationType,
} from "@soos-io/api-client";
import { version } from "../package.json";
import { ZAPCommandGenerator, ZAPReportTransformer } from "./utilities";
import AnalysisService from "@soos-io/api-client/dist/services/AnalysisService";
import AnalysisArgumentParser, {
  IBaseScanArguments,
} from "@soos-io/api-client/dist/services/AnalysisArgumentParser";
import { SOOS_DAST_CONSTANTS } from "./constants";

export interface SOOSDASTAnalysisArgs extends IBaseScanArguments {
  ajaxSpider: boolean;
  apiScanFormat: ApiScanFormat;
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
  contextFile: string;
  debug: boolean;
  disableRules: string;
  excludeUrlsFile: string;
  fullScanMinutes: number;
  oauthParameters: string;
  oauthTokenUrl: string;
  otherOptions: string;
  outputFormat: OutputFormat;
  /**
   * @deprecated Only here for backwards compatibility, do not reference.
   */
  requestCookies: string;
  requestHeaders: string;
  scanMode: ScanMode;
  updatePlugins: boolean;
  targetURL: string;
}

class SOOSDASTAnalysis {
  constructor(private args: SOOSDASTAnalysisArgs) {}

  static parseArgs(): SOOSDASTAnalysisArgs {
    const analysisArgumentParser = AnalysisArgumentParser.create(
      IntegrationName.SoosDast,
      IntegrationType.Script,
      ScanType.DAST,
      version,
    );

    analysisArgumentParser.addBaseScanArguments();

    analysisArgumentParser.argumentParser.add_argument("--ajaxSpider", {
      help: "Ajax Spider - Use the ajax spider in addition to the traditional one. Additional information: https://www.zaproxy.org/docs/desktop/addons/ajax-spider/.",
      action: "store_true",
      required: false,
    });

    analysisArgumentParser.addEnumArgument(
      analysisArgumentParser.argumentParser,
      "--apiScanFormat",
      ApiScanFormat,
      {
        help: "Target API format, OpenAPI, SOAP or GraphQL.",
        required: false,
      },
    );

    analysisArgumentParser.argumentParser.add_argument("--authDelayTime", {
      help: "Delay time in seconds to wait for the page to load after performing actions in the form. (Used only on authFormType: wait_for_password and multi_page)",
      default: SOOS_DAST_CONSTANTS.AuthDelayTime,
      required: false,
    });

    analysisArgumentParser.addEnumArgument(
      analysisArgumentParser.argumentParser,
      "--authFormType",
      FormTypes,
      {
        help: `Form type of the login URL options are: simple (all fields are displayed at once),
             wait_for_password (Password field is displayed only after username is filled),
             or multi_page (Password field is displayed only after username is filled and submit is clicked).`,
        default: FormTypes.Simple,
        required: false,
      },
    );

    analysisArgumentParser.argumentParser.add_argument("--authLoginURL", {
      help: "Login URL to use when authentication is required.",
      required: false,
    });

    analysisArgumentParser.argumentParser.add_argument("--authPassword", {
      help: "Password to use when authentication is required.",
      required: false,
    });

    analysisArgumentParser.argumentParser.add_argument("--authPasswordField", {
      help: "Password input id to use when authentication is required.",
      required: false,
    });

    analysisArgumentParser.argumentParser.add_argument("--authSecondSubmitField", {
      help: "Second submit button id to use when authentication is required.",
      required: false,
    });

    analysisArgumentParser.addEnumArgument(
      analysisArgumentParser.argumentParser,
      "--authSubmitAction",
      SubmitActions,
      {
        help: "Submit action to perform on form filled. Options: click or submit.",
        required: false,
      },
    );

    analysisArgumentParser.argumentParser.add_argument("--authSubmitField", {
      help: "Submit button id to use when authentication is required.",
      required: false,
    });

    analysisArgumentParser.argumentParser.add_argument("--authUsername", {
      help: "Username to use when authentication is required.",
      required: false,
    });

    analysisArgumentParser.argumentParser.add_argument("--authUsernameField", {
      help: "Username input id to use when authentication is required.",
      required: false,
    });

    analysisArgumentParser.argumentParser.add_argument("--authVerificationURL", {
      help: "URL used to verify authentication success, should be an URL that is expected to throw 200/302 during any authFormType authentication. If authentication fails when this URL is provided, the scan will be terminated. Supports plain URL or regex URL.",
      required: false,
    });

    analysisArgumentParser.argumentParser.add_argument("--bearerToken", {
      help: "Bearer token, adds a Authentication header with the token value.",
      required: false,
    });

    analysisArgumentParser.argumentParser.add_argument("--contextFile", {
      help: "Context file which will be loaded prior to scanning the target.",
      nargs: "*",
      required: false,
    });

    analysisArgumentParser.argumentParser.add_argument("--debug", {
      help: "Enable debug logging for ZAP.",
      action: "store_true",
      required: false,
    });

    analysisArgumentParser.argumentParser.add_argument("--disableRules", {
      help: "Comma separated list of ZAP rules IDs to disable. List for reference https://www.zaproxy.org/docs/alerts/",
      required: false,
      nargs: "*",
    });

    analysisArgumentParser.argumentParser.add_argument("--excludeUrlsFile", {
      help: "Path to a file containing regex URLs to exclude, one per line.",
      required: false,
    });

    analysisArgumentParser.argumentParser.add_argument("--fullScanMinutes", {
      help: "Number of minutes for the spider to run.",
      required: false,
    });

    analysisArgumentParser.argumentParser.add_argument("--oauthParameters", {
      help: `Parameters to be added to the oauth token request. (eg --oauthParameters="client_id:clientID, client_secret:clientSecret, grant_type:client_credentials").`,
      required: false,
      nargs: "*",
    });

    analysisArgumentParser.argumentParser.add_argument("--oauthTokenUrl", {
      help: "The authentication URL that grants the access_token.",
      required: false,
    });

    analysisArgumentParser.argumentParser.add_argument("--otherOptions", {
      help: "Other command line arguments sent directly to the script for items not supported by other command line arguments",
      required: false,
      nargs: "*",
    });

    analysisArgumentParser.addEnumArgument(
      analysisArgumentParser.argumentParser,
      "--outputFormat",
      OutputFormat,
      {
        help: "Output format for vulnerabilities: only the value SARIF is available at the moment",
        required: false,
      },
    );

    analysisArgumentParser.argumentParser.add_argument("--requestCookies", {
      help: "DEPRECATED. This parameter has no effect.",
      nargs: "*",
      required: false,
    });

    analysisArgumentParser.argumentParser.add_argument("--requestHeaders", {
      help: "Set extra headers for the requests to the target URL",
      nargs: "*",
      required: false,
    });

    analysisArgumentParser.addEnumArgument(
      analysisArgumentParser.argumentParser,
      "--scanMode",
      ScanMode,
      {
        help: "Scan Mode - Available modes: baseline, fullscan, and apiscan (for more information about scan modes visit https://github.com/soos-io/soos-dast#scan-modes)",
        default: ScanMode.Baseline,
        required: false,
      },
    );

    analysisArgumentParser.argumentParser.add_argument("--updatePlugins", {
      help: "Set to true to update the ZAP plugins before running.",
      action: "store_true",
      required: false,
    });

    analysisArgumentParser.argumentParser.add_argument("targetURL", {
      help: "Target URL - URL of the site or api to scan. The URL should include the protocol. Ex: https://www.example.com",
    });

    soosLogger.info("Parsing arguments");
    return analysisArgumentParser.parseArguments();
  }

  async runAnalysis(): Promise<void> {
    const scanType = ScanType.DAST;
    const soosAnalysisService = AnalysisService.create(this.args.apiKey, this.args.apiURL);

    if (this.args.requestCookies && this.args.requestCookies.length > 0) {
      soosLogger.warn(
        "--requestCookies is deprecated and will be removed. The parameter has no effect.",
      );
    }

    let projectHash: string | undefined;
    let branchHash: string | undefined;
    let analysisId: string | undefined;
    let scanStatusUrl: string | undefined;
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
      const result = await soosAnalysisService.setupScan({
        clientId: this.args.clientId,
        projectName: this.args.projectName,
        commitHash: this.args.commitHash,
        branchName: this.args.branchName,
        buildVersion: this.args.buildVersion,
        buildUri: this.args.buildURI,
        branchUri: this.args.branchURI,
        integrationType: this.args.integrationType,
        operatingEnvironment: this.args.operatingEnvironment,
        integrationName: this.args.integrationName,
        appVersion: this.args.appVersion,
        scriptVersion: this.args.scriptVersion,
        contributingDeveloperAudit:
          !this.args.contributingDeveloperId ||
          !this.args.contributingDeveloperSource ||
          !this.args.contributingDeveloperSourceName
            ? []
            : [
                {
                  contributingDeveloperId: this.args.contributingDeveloperId,
                  source: this.args.contributingDeveloperSource,
                  sourceName: this.args.contributingDeveloperSourceName,
                },
              ],
        scanType,
        toolName: SOOS_DAST_CONSTANTS.Tool,
        toolVersion: SOOS_DAST_CONSTANTS.ToolVersion,
      });
      projectHash = result.projectHash;
      branchHash = result.branchHash;
      analysisId = result.analysisId;
      scanStatusUrl = result.scanStatusUrl;

      const zapCommandGenerator = new ZAPCommandGenerator(this.args);
      soosLogger.info(`Generating ZAP command... ${this.args.scanMode}`);
      const command = zapCommandGenerator.runCommandGeneration(this.args.scanMode);
      soosLogger.info(`Running command: ${command}`);
      await SOOSDASTAnalysis.runZap(command);
      const runSuccess = fs.existsSync(SOOS_DAST_CONSTANTS.Files.ReportScanResultFile);
      soosLogger.info(`Scan finished with success: ${runSuccess}`);

      const data = JSON.parse(
        fs.readFileSync(
          SOOS_DAST_CONSTANTS.Files.ReportScanResultFile,
          SOOS_CONSTANTS.FileUploads.Encoding,
        ),
      );

      ZAPReportTransformer.transformReport(data);

      const formData = new FormData();

      formData.append("resultVersion", data["@version"]);
      formData.append(
        "file",
        convertStringToBase64(
          JSON.stringify(
            JSON.parse(
              fs.readFileSync(
                SOOS_DAST_CONSTANTS.Files.ReportScanResultFile,
                SOOS_CONSTANTS.FileUploads.Encoding,
              ),
            ),
          ),
        ),
        "base64Manifest",
      );
      soosLogger.logLineSeparator();
      soosLogger.info(`Starting report results processing`);
      soosLogger.info(`Uploading scan result for project ${this.args.projectName}...`);
      await soosAnalysisService.analysisApiClient.uploadScanToolResult({
        clientId: this.args.clientId,
        projectHash,
        branchHash,
        scanType,
        scanId: analysisId,
        resultFile: formData,
        hasMoreThanMaximumFiles: false,
      });
      soosLogger.info(`Scan result uploaded successfully`);

      if (data["discoveredUrls"]?.length) {
        soosLogger.always(`(${data["discoveredUrls"].length} URLs discovered)`);
      }

      const scanStatus = await soosAnalysisService.waitForScanToFinish({
        scanStatusUrl: result.scanStatusUrl,
        scanUrl: result.scanUrl,
        scanType,
      });

      if (this.args.outputFormat !== undefined) {
        await soosAnalysisService.generateFormattedOutput({
          clientId: this.args.clientId,
          projectHash: result.projectHash,
          projectName: this.args.projectName,
          branchHash: result.branchHash,
          scanType,
          analysisId: result.analysisId,
          outputFormat: this.args.outputFormat,
          workingDirectory: "/zap/wrk",
        });
      }

      const exitCodeWithMessage = getAnalysisExitCodeWithMessage(
        scanStatus,
        this.args.integrationName,
        this.args.onFailure,
      );
      soosLogger.always(`${exitCodeWithMessage.message} - exit ${exitCodeWithMessage.exitCode}`);
      exit(exitCodeWithMessage.exitCode);
    } catch (error) {
      if (projectHash && branchHash && analysisId)
        await soosAnalysisService.updateScanStatus({
          clientId: this.args.clientId,
          projectHash,
          branchHash,
          scanType,
          analysisId: analysisId,
          status: ScanStatus.Error,
          message: "Error while performing scan.",
          scanStatusUrl,
        });
      soosLogger.error(error);
      soosLogger.always(`${error} - exit 1`);
      exit(1);
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
      soosLogger.info("Configuration read");
      soosLogger.debug(
        JSON.stringify(
          obfuscateProperties(args as unknown as Record<string, unknown>, [
            "apiKey",
            "authPassword",
            "bearerToken",
          ]),
          null,
          2,
        ),
      );
      soosLogger.logLineSeparator();
      const soosDASTAnalysis = new SOOSDASTAnalysis(args);
      await soosDASTAnalysis.runAnalysis();
    } catch (error) {
      soosLogger.error(`Error on createAndRun: ${error}`);
      soosLogger.always(`Error on createAndRun: ${error} - exit 1`);
      exit(1);
    }
  }
}

SOOSDASTAnalysis.createAndRun();
