import * as fs from "fs";
import FormData from "form-data";
import { spawn, execSync } from "child_process";
import { ApiScanFormat, FormTypes, ScanMode, SubmitActions } from "./enums";
import { exit } from "process";
import {
  isUrlAvailable,
  convertStringToBase64,
  obfuscateProperties,
  getAnalysisExitCode,
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
import { ZAPCommandGenerator } from "./utilities";
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
  checkoutDir: string;
  contextFile: string;
  debug: boolean;
  disableRules: string;
  fullScanMinutes: number;
  oauthParameters: string;
  oauthTokenUrl: string;
  otherOptions: string;
  outputFormat: OutputFormat;
  requestCookies: string;
  requestHeaders: string;
  scanMode: ScanMode;
  targetURL: string;
  updateAddons: boolean;
}

class SOOSDASTAnalysis {
  constructor(private args: SOOSDASTAnalysisArgs) {}

  static parseArgs(): SOOSDASTAnalysisArgs {
    const analysisArgumentParser = AnalysisArgumentParser.create(ScanType.DAST);

    analysisArgumentParser.addBaseScanArguments(
      IntegrationName.SoosDast,
      IntegrationType.Script,
      version,
    );

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
      help: "URL used to verify authentication success, should be an URL that is expected to throw 200/302 during any authFormType authentication. If authentication fails when this URL is provided, the scan will be terminated.",
      required: false,
    });

    analysisArgumentParser.argumentParser.add_argument("--bearerToken", {
      help: "Bearer token, adds a Authentication header with the token value.",
      required: false,
    });

    analysisArgumentParser.argumentParser.add_argument("--checkoutDir", {
      help: "Directory where the SARIF file will be created, used by Github Actions.",
      required: false,
      nargs: "*",
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

    analysisArgumentParser.argumentParser.add_argument("--requestCookies", {
      help: "Set Cookie values for the requests to the target URL",
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

    analysisArgumentParser.argumentParser.add_argument("--updateAddons", {
      help: "Update ZAP Addons - Update ZAP Addons before running the scan.",
      action: "store_true",
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

      execSync("mkdir -p ~/.ZAP/reports /root/.ZAP/reports");

      execSync("cp -R /zap/reports/traditional-json-headers ~/.ZAP/reports/traditional-json");
      execSync("cp -R /zap/reports/traditional-json-headers /root/.ZAP/reports/traditional-json");

      const zapCommandGenerator = new ZAPCommandGenerator(this.args);
      soosLogger.info(`Generating ZAP command... ${this.args.scanMode}`);
      const command = zapCommandGenerator.runCommandGeneration(this.args.scanMode);
      soosLogger.info(`Running command: ${command}`);
      await SOOSDASTAnalysis.runZap(command);
      const runSuccess = fs.existsSync(SOOS_DAST_CONSTANTS.Files.ReportScanResultFile);
      soosLogger.info(`Scan finished with success: ${runSuccess}`);

      const discoveredUrls =
        fs.existsSync(SOOS_DAST_CONSTANTS.Files.SpideredUrlsFile) &&
        fs.statSync(SOOS_DAST_CONSTANTS.Files.SpideredUrlsFile).isFile()
          ? fs
              .readFileSync(SOOS_DAST_CONSTANTS.Files.SpideredUrlsFile, "utf-8")
              .split("\n")
              .filter((url) => url.trim() !== "")
          : [];

      const data = JSON.parse(
        fs.readFileSync(SOOS_DAST_CONSTANTS.Files.ReportScanResultFile, "utf-8"),
      );
      data["discoveredUrls"] = discoveredUrls;
      fs.writeFileSync(
        SOOS_DAST_CONSTANTS.Files.ReportScanResultFile,
        JSON.stringify(data, null, 4),
      );
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
          workingDirectory: this.args.checkoutDir,
        });
      }

      const exitCode = getAnalysisExitCode(
        scanStatus,
        this.args.integrationName,
        this.args.onFailure,
      );
      soosLogger.debug(`Exiting with code ${exitCode}`);
      exit(exitCode);
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
          2,
        ),
      );
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
