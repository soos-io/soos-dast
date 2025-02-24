import * as fs from "fs";
import { SOOS_DAST_CONSTANTS } from "../constants";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type ReportData = any;

export class ZAPReportTransformer {
  public static transformReport(reportData: ReportData): void {
    this.addDiscoveredUrls(reportData);
    this.obfuscateFields(reportData);
    this.saveReportContent(reportData);
  }

  public static addDiscoveredUrls(reportData: ReportData): void {
    this.addArrayPropertyToReportFromFile(
      reportData,
      "discoveredUrls",
      SOOS_DAST_CONSTANTS.Files.DiscoveredUrlsFile,
    );
  }

  public static obfuscateFields(reportData: ReportData): void {
    for (const key in reportData) {
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
    reportData: ReportData,
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

  private static saveReportContent = (reportData: ReportData) => {
    fs.writeFileSync(
      SOOS_DAST_CONSTANTS.Files.ReportScanResultFile,
      JSON.stringify(reportData, null, 4),
    );
  };
}
