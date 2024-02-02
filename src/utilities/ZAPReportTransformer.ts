import * as fs from "fs";
import { SOOS_DAST_CONSTANTS } from "../constants";

export class ZAPReportTransformer {
  // TODO - PA-12868 Rework this approach
  public static transformReport(reportData: any): void {
    this.addDiscoveredUrls(reportData);
    this.obfuscateFields(reportData);
    this.saveReportContent(reportData);
  }

  public static addDiscoveredUrls(reportData: any): void {
    const discoveredUrls =
      fs.existsSync(SOOS_DAST_CONSTANTS.Files.SpideredUrlsFile) &&
      fs.statSync(SOOS_DAST_CONSTANTS.Files.SpideredUrlsFile).isFile()
        ? fs
            .readFileSync(SOOS_DAST_CONSTANTS.Files.SpideredUrlsFile, "utf-8")
            .split("\n")
            .filter((url) => url.trim() !== "")
        : [];

    reportData["discoveredUrls"] = discoveredUrls;
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
