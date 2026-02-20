import * as fs from "fs";
import FormData from "form-data";
import { spawn } from "child_process";
import { ApiScanFormat, FormTypes, ScanMode, SubmitActions } from "./enums";
import { exit } from "process";
import {
  isUrlAvailable,
  obfuscateProperties,
  getAnalysisExitCodeWithMessage,
  isScanDone,
  obfuscateCommandLine,
  reassembleCommandLine,
  StringUtilities,
} from "@soos-io/api-client/dist/utilities";
import {
  ScanStatus,
  ScanType,
  soosLogger,
  IntegrationName,
  IntegrationType,
  AttributionFormatEnum,
  AttributionFileTypeEnum,
} from "@soos-io/api-client";
import { version } from "../package.json";
import { ZAPCommandGenerator } from "./utilities/ZAPCommandGenerator";
import { ZAPReportTransformer } from "./utilities/ZAPReportTransformer";
import AnalysisService from "@soos-io/api-client/dist/services/AnalysisService";
import AnalysisArgumentParser, {
  IBaseScanArguments,
} from "@soos-io/api-client/dist/services/AnalysisArgumentParser";
import { SOOS_DAST_CONSTANTS } from "./constants";

export interface IDASTAnalysisArgs extends IBaseScanArguments {
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
  otherOptions: string;
  requestHeaders: string;
  scanMode: ScanMode;
  targetURL: string;
  timeout?: number;
}

const splitValueRegex = new RegExp(
  /^([A-Za-z0-9\-_\\/:.]+:[A-Za-z0-9\-_\\/:.]+)(?:,\s*([A-Za-z0-9\-_\\/:.]+:[A-Za-z0-9\-_\\/:.]+))*$/,
);

const parseArgs = (): IDASTAnalysisArgs => {
  const analysisArgumentParser = AnalysisArgumentParser.create(
    IntegrationName.SoosDast,
    IntegrationType.Script,
    ScanType.DAST,
    version,
  );

  analysisArgumentParser.addArgument(
    "ajaxSpider",
    "Ajax Spider - Use the ajax spider in addition to the traditional one. Additional information: https://www.zaproxy.org/docs/desktop/addons/ajax-spider/.",
    {
      isFlag: true,
    },
  );

  analysisArgumentParser.addEnumArgument(
    "apiScanFormat",
    ApiScanFormat,
    "Target API format, OpenAPI, SOAP or GraphQL.",
    { defaultValue: ApiScanFormat.OpenAPI },
  );

  analysisArgumentParser.addArgument(
    "authDelayTime",
    "Delay time in seconds to wait for the page to load after performing actions in the form. (Used only on authFormType: wait_for_password and multi_page)",
    {
      defaultValue: SOOS_DAST_CONSTANTS.AuthDelayTime,
    },
  );

  analysisArgumentParser.addEnumArgument(
    "authFormType",
    FormTypes,
    "Form type of the login URL options are: simple (all fields are displayed at once), wait_for_password (Password field is displayed only after username is filled), or multi_page (Password field is displayed only after username is filled and submit is clicked).",
    {
      defaultValue: FormTypes.Simple,
    },
  );

  analysisArgumentParser.addArgument(
    "authLoginURL",
    "Login URL to use when authentication is required.",
    {
      argParser: (value: string) => {
        if (
          !value.toLowerCase().startsWith("http://") &&
          !value.toLowerCase().startsWith("https://")
        ) {
          throw new Error("Invalid authLoginURL. Expected http(s):// URL.");
        }

        return value;
      },
    },
  );

  analysisArgumentParser.addArgument(
    "authPassword",
    "Password to use when authentication is required.",
  );

  analysisArgumentParser.addArgument(
    "authPasswordField",
    "Password input id to use when authentication is required.",
  );

  analysisArgumentParser.addArgument(
    "authSecondSubmitField",
    "Second submit button id to use when authentication is required.",
  );

  analysisArgumentParser.addEnumArgument(
    "authSubmitAction",
    SubmitActions,
    "Submit action to perform on form filled. Options: click or submit.",
    {
      defaultValue: SubmitActions.Click,
    },
  );

  analysisArgumentParser.addArgument(
    "authSubmitField",
    "Submit button id to use when authentication is required.",
  );

  analysisArgumentParser.addArgument(
    "authUsername",
    "Username to use when authentication is required.",
  );

  analysisArgumentParser.addArgument(
    "authUsernameField",
    "Username input id to use when authentication is required.",
  );

  analysisArgumentParser.addArgument(
    "authVerificationURL",
    "URL used to verify authentication success, should be an URL that is expected to throw 200/302 during any authFormType authentication. If authentication fails when this URL is provided, the scan will be terminated. Supports plain URL or regex URL.",
    {
      argParser: (value: string) => {
        if (
          !value.toLowerCase().startsWith("http://") &&
          !value.toLowerCase().startsWith("https://")
        ) {
          throw new Error("Invalid authVerificationURL. Expected http(s):// URL.");
        }

        return value;
      },
    },
  );

  analysisArgumentParser.addArgument(
    "bearerToken",
    "Bearer token, adds a Authentication header with the token value.",
  );

  analysisArgumentParser.addArgument(
    "contextFile",
    "Context file which will be loaded prior to scanning the target.",
  );

  analysisArgumentParser.addArgument("debug", "Enable debug logging for ZAP.", {
    isFlag: true,
  });

  analysisArgumentParser.addArgument(
    "disableRules",
    "Comma separated list of ZAP rules IDs to disable. List for reference https://www.zaproxy.org/docs/alerts/",
  );

  analysisArgumentParser.addArgument(
    "excludeUrlsFile",
    "Path to a file containing regex URLs to exclude, one per line.",
  );

  analysisArgumentParser.addArgument("fullScanMinutes", "Number of minutes for the spider to run.");

  analysisArgumentParser.addArgument(
    "otherOptions",
    "Other command line arguments sent directly to the script for items not supported by other command line arguments",
  );

  analysisArgumentParser.addArgument(
    "requestHeaders",
    "Set extra headers for the requests to the target URL",
    {
      argParser: (value: string) => {
        // Ensures format h1:v1,h2:v2,...
        if (!splitValueRegex.test(value)) {
          throw new Error("Invalid requestHeaders format. Expected h1:v1,h2:v2,...,hn:vn");
        }

        return value;
      },
    },
  );

  analysisArgumentParser.addEnumArgument(
    "scanMode",
    ScanMode,
    "Scan Mode - Available modes: baseline, fullscan, and apiscan (for more information about scan modes visit https://github.com/soos-io/soos-dast#scan-modes)",
    {
      defaultValue: ScanMode.Baseline,
    },
  );

  analysisArgumentParser.addArgument(
    "targetURL",
    "Target URL - URL of the site or api to scan. The URL should include the protocol. Ex: https://www.example.com",
    { useNoOptionKey: true, required: true },
  );

  analysisArgumentParser.addArgument(
    "timeout",
    "Max time in minutes to wait for ZAP to start and the passive scan to run",
  );
  return analysisArgumentParser.parseArguments<IDASTAnalysisArgs>(process.argv);
};

const runZap = async (command: string): Promise<void> => {
  return new Promise((resolve, reject) => {
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
};

const runAnalysis = async (args: IDASTAnalysisArgs): Promise<void> => {
  const scanType = ScanType.DAST;
  const soosAnalysisService = AnalysisService.create(args.apiKey, args.apiURL);

  let projectHash: string | undefined;
  let branchHash: string | undefined;
  let analysisId: string | undefined;
  let scanStatusUrl: string | undefined;
  let scanStatus: ScanStatus | undefined;

  try {
    soosLogger.info(`Project Name: ${args.projectName}`);
    soosLogger.info(`Scan Mode: ${args.scanMode}`);
    soosLogger.info(`API URL: ${args.apiURL}`);
    soosLogger.info(`Target URL: ${args.targetURL}`);

    if (args.scanMode !== ScanMode.ApiScan) {
      soosLogger.info(`Checking if url '${args.targetURL}' is available...`);
      const urlAvailable = await isUrlAvailable(args.targetURL);
      if (!urlAvailable) {
        soosLogger.error(`The URL ${args.targetURL} is not available.`);
        exit(1);
      }
    }

    soosLogger.info(`Creating scan for project ${args.projectName}...`);
    const result = await soosAnalysisService.setupScan({
      clientId: args.clientId,
      projectName: args.projectName,
      commitHash: args.commitHash,
      branchName: args.branchName,
      buildVersion: args.buildVersion,
      buildUri: args.buildURI,
      branchUri: args.branchURI,
      integrationType: args.integrationType,
      operatingEnvironment: args.operatingEnvironment,
      integrationName: args.integrationName,
      appVersion: args.appVersion,
      scriptVersion: args.scriptVersion,
      contributingDeveloperAudit: [
        {
          contributingDeveloperId: args.contributingDeveloperId,
          source: args.contributingDeveloperSource,
          sourceName: args.contributingDeveloperSourceName,
        },
      ],
      scanType,
      toolName: SOOS_DAST_CONSTANTS.Tool,
      toolVersion: SOOS_DAST_CONSTANTS.ToolVersion,
      scanMode: args.scanMode,
      commandLine:
        process.argv.length > 2
          ? obfuscateCommandLine(
              reassembleCommandLine(process.argv.slice(2)),
              SOOS_DAST_CONSTANTS.ObfuscatedArguments.map((a) => `--${a}`),
            )
          : null,
    });

    projectHash = result.projectHash;
    branchHash = result.branchHash;
    analysisId = result.analysisId;
    scanStatusUrl = result.scanStatusUrl;

    const zapCommandGenerator = new ZAPCommandGenerator(args);
    soosLogger.info(`Generating ZAP command... ${args.scanMode}`);
    const command = zapCommandGenerator.createCommand(args.scanMode);
    soosLogger.info(`Running command: ${command}`);
    await runZap(command);
    const doesReportExist = fs.existsSync(SOOS_DAST_CONSTANTS.Files.ReportScanResultFile);
    soosLogger.info(`Scan finished with success: ${doesReportExist}`);

    const fileContent = await fs.promises.readFile(SOOS_DAST_CONSTANTS.Files.ReportScanResultFile, {
      encoding: "utf-8",
    });
    const report = JSON.parse(fileContent);
    ZAPReportTransformer.transformReport(report);

    const formData = new FormData();
    formData.append("resultVersion", report["@version"]);
    formData.append(
      "file",
      StringUtilities.toBase64(JSON.stringify(report)),
      SOOS_DAST_CONSTANTS.Files.ReportScanResultFilename,
    );

    soosLogger.info(`Starting report results processing`);
    soosLogger.info(`Uploading scan result for project ${args.projectName}...`);
    await soosAnalysisService.analysisApiClient.uploadScanToolResult({
      clientId: args.clientId,
      projectHash,
      branchHash,
      scanType,
      scanId: analysisId,
      resultFile: formData,
      hasMoreThanMaximumFiles: false,
    });
    soosLogger.info(`Scan result uploaded successfully`);

    if (report["discoveredUrls"]?.length) {
      soosLogger.always(`(${report["discoveredUrls"].length} URLs discovered)`);
    }

    scanStatus = await soosAnalysisService.waitForScanToFinish({
      scanStatusUrl: result.scanStatusUrl,
      scanUrl: result.scanUrl,
      scanType,
    });

    if (
      isScanDone(scanStatus) &&
      args.exportFormat !== AttributionFormatEnum.Unknown &&
      args.exportFileType !== AttributionFileTypeEnum.Unknown
    ) {
      await soosAnalysisService.generateFormattedOutput({
        clientId: args.clientId,
        projectHash: result.projectHash,
        projectName: args.projectName,
        branchHash: result.branchHash,
        analysisId: result.analysisId,
        format: args.exportFormat,
        fileType: args.exportFileType,
        workingDirectory: "/zap/wrk",
      });
    }

    const exitCodeWithMessage = getAnalysisExitCodeWithMessage(
      scanStatus,
      args.integrationName,
      args.onFailure,
    );
    soosLogger.always(`${exitCodeWithMessage.message} - exit ${exitCodeWithMessage.exitCode}`);
    exit(exitCodeWithMessage.exitCode);
  } catch (error) {
    if (projectHash && branchHash && analysisId && (!scanStatus || !isScanDone(scanStatus))) {
      await soosAnalysisService.updateScanStatus({
        clientId: args.clientId,
        projectHash,
        branchHash,
        scanType,
        analysisId: analysisId,
        status: ScanStatus.Error,
        message: "Error while performing scan.",
        scanStatusUrl,
      });
    }
    soosLogger.error(error);
    soosLogger.always(`${error} - exit 1`);
    exit(1);
  }
};

(async () => {
  try {
    const args = parseArgs();
    soosLogger.setMinLogLevel(args.logLevel);
    soosLogger.always("Starting SOOS DAST Analysis");
    soosLogger.debug(
      JSON.stringify(
        obfuscateProperties(
          args as unknown as Record<string, unknown>,
          SOOS_DAST_CONSTANTS.ObfuscatedArguments,
        ),
        null,
        2,
      ),
    );

    await runAnalysis(args);
  } catch (error) {
    soosLogger.error(`Error on execution: ${error}`);
    soosLogger.always(`Error on execution: ${error} - exit 1`);
    exit(1);
  }
})();
