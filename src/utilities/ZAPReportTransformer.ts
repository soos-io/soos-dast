import * as fs from "fs";
import { SOOS_DAST_CONSTANTS } from "../constants";

export class ZAPReportTransformer {
  // TODO - PA-12868 Rework this approach
  public static transformReport(reportData: any): void {
    this.addCoreUrls(reportData);
    this.addDiscoveredUrls(reportData);
    this.obfuscateFields(reportData);
    this.saveReportContent(reportData);
  }

  public static addCoreUrls(reportData: any): void {
    this.addArrayPropertyToReportFromFile(
      reportData,
      "coreUrls",
      SOOS_DAST_CONSTANTS.Files.CoreUrlsFile,
    );
  }

  public static addDiscoveredUrls(reportData: any): void {
    this.addArrayPropertyToReportFromFile(
      reportData,
      "discoveredUrls",
      SOOS_DAST_CONSTANTS.Files.SpideredUrlsFile,
    );
  }

  public static obfuscateFields(reportData: any): void {
    for (let key in reportData) {
      if (typeof reportData[key] === "object" && reportData[key] !== null) {
        this.obfuscateFields(reportData[key]);
      } else {
        if (key === "request-header") {
          reportData[key] = this.obfuscateBearerToken(reportData[key]);
        }
      }
    }
  }

  private static addArrayPropertyToReportFromFile(
    reportData: any,
    name: string,
    file: string,
  ): void {
    const lines =
      fs.existsSync(file) && fs.statSync(file).isFile()
        ? fs
            .readFileSync(file, "utf-8")
            .split("\n")
            .filter((line) => line.trim() !== "")
        : [];

    reportData[name] = lines;
  }

  private static obfuscateBearerToken(field: string): string {
    return field.replace(/(Authorization:\s*)[^\r\n]+/, "$1****");
  }

  private static saveReportContent = (reportData: any) => {
    fs.writeFileSync(
      SOOS_DAST_CONSTANTS.Files.ReportScanResultFile,
      JSON.stringify(reportData, null, 4),
    );
  };
}
