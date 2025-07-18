# [SOOS DAST](https://soos.io/dast-product/)

SOOS is an independent software security company, located in Winooski, VT USA, building security software for your team. [SOOS, Software security, simplified](https://soos.io).

Use SOOS to scan your software for [vulnerabilities](https://app.soos.io/research/vulnerabilities) and [open source license](https://app.soos.io/research/licenses) issues with [SOOS Core SCA](https://soos.io/products/sca). [Generate and ingest SBOMs](https://soos.io/products/sbom-manager). [Export reports](https://kb.soos.io/project-exports-and-reports) to industry standards. Govern your open source dependencies. Run the [SOOS DAST vulnerability scanner](https://soos.io/products/dast) against your web apps or APIs. [Scan your Docker containers](https://soos.io/products/containers) for vulnerabilities. Check your source code for issues with [SAST Analysis](https://soos.io/products/sast).

[Demo SOOS](https://app.soos.io/demo) or [Register for a Free Trial](https://app.soos.io/register).

If you maintain an Open Source project, sign up for the Free as in Beer [SOOS Community Edition](https://soos.io/products/community-edition).

## SOOS Badge Status
[![Dependency Vulnerabilities](https://img.shields.io/endpoint?url=https%3A%2F%2Fapi-hooks.soos.io%2Fapi%2Fshieldsio-badges%3FbadgeType%3DDependencyVulnerabilities%26pid%3Dvmh4zz11b%26)](https://app.soos.io)
[![Out Of Date Dependencies](https://img.shields.io/endpoint?url=https%3A%2F%2Fapi-hooks.soos.io%2Fapi%2Fshieldsio-badges%3FbadgeType%3DOutOfDateDependencies%26pid%3Dvmh4zz11b%26)](https://app.soos.io)

## Requirements
- [Docker](https://www.docker.com/get-started)
- Have your application or website reachable via URL.

## How to Use
To start the scan you need to run this command from a terminal:
``` shell
docker run -u zap -it --rm soosio/dast <parameters>
```

The basic command to run a baseline scan would look like:
`docker run -u zap -it --rm soosio/dast --clientId=<YOUR_CLIENT_ID> --apiKey=<YOUR_API_KEY> --projectName="<YOUR_PROJECT_NAME>" <YOUR_TARGET_URL>`

### Arguments

| Argument | Required | Description |
| --- | --- | --- |
| `targetURL` | Yes | Target URL - URL of the site or api to scan. The URL should include the protocol. Ex: https://www.example.com |

### Client Parameters

| Argument | Default | Description |
| --- | --- | --- |
| `--ajaxSpider` |  | Ajax Spider - Use the ajax spider in addition to the traditional one. Additional information: https://www.zaproxy.org/docs/desktop/addons/ajax-spider/ |
| `--apiKey` |  | SOOS API Key - get yours from [SOOS Integration](https://app.soos.io/integrate/dast). Uses `SOOS_API_KEY` env value if present. |
| `--authDelayTime` | `5` | Delay time in seconds to wait for the page to load after performing actions in the form. (Used only on authFormType: wait_for_password and multi_page) |
| `--authFormType` | `simple` | simple (all fields are displayed at once), wait_for_password (Password field is displayed only after username is filled), or multi_page (Password field is displayed only after username is filled and submit is clicked) |
| `--authLoginURL` |  | Login url to use when authentication is required |
| `--authPassword` |  | Password to use when authentication is required |
| `--authPasswordField` |  | Password input id to use when authentication is required |
| `--authSecondSubmitField` |  | Second submit button id/name/XPath to use when authentication is required (for multi-page forms) |
| `--authSubmitAction` |  | Submit action to perform on form filled. Options: click or submit |
| `--authSubmitField` |  | Submit button id/name/XPath to use when authentication is required |
| `--authUsername` |  | Username to use when authentication is required |
| `--authUsernameField` |  | Username input id to use when authentication is required |
| `--authVerificationURL` |  | URL used to verify authentication success, should be an URL that is expected to throw 200/302 during any authFormType authentication. If authentication fails when this URL is provided, the scan will be terminated. Supports plain URL or regex URL.|
| `--bearerToken` |  | Bearer token to authenticate |
| `--branchName` |  | The name of the branch from the SCM System |
| `--branchURI` |  | The URI to the branch from the SCM System |
| `--buildURI` |  | URI to CI build info |
| `--buildVersion` |  | Version of application build artifacts |
| `--clientId` |  | SOOS Client ID - get yours from [SOOS Integration](https://app.soos.io/integrate/sast). Uses `SOOS_API_CLIENT` env value if present. |
| `--commitHash` |  | The commit hash value from the SCM System |
| `--contextFile` |  | Context file which will be loaded prior to scanning the target |
| `--debug` |  | Enable debug logging for ZAP. |
| `--excludeUrlsFile` | | Path to a file containing regex URLs to exclude, one per line. eg `--excludeUrlsFile=exclude_urls.txt`
| `--disableRules` |  | Comma separated list of ZAP rules IDs to disable. List for reference https://www.zaproxy.org/docs/alerts/ |
| `--exportFormat`   |  | Write the scan result to this file format. Options: CsafVex, CycloneDx, Sarif, Spdx, SoosIssues, SoosLicenses, SoosPackages, SoosVulnerabilities |
| `--exportFileType` |  | Write the scan result to this file type (when used with exportFormat). Options: Csv, Html, Json, Text, Xml                                       |
| `--fullScanMinutes` |  | Number of minutes for the spider to run |
| `--logLevel` |  | Minimum level to show logs: DEBUG INFO, WARN, FAIL, ERROR. |
| `--onFailure` | `continue_on_failure` | Action to perform when the scan fails. Options: fail_the_build, continue_on_failure |
| `--operatingEnvironment` |  | Set Operating environment for information purposes only |
| `--otherOptions` |  | Additional command line arguments for items not supported by the set of parameters above |
| `--projectName` |  | Project Name - this is what will be displayed in the SOOS app |
| `--requestHeaders` |  | Set extra Header requests |
| `--scanMode` | `baseline` | Scan Mode - Available modes: baseline, fullscan, and apiscan (for more information about scan modes visit https://github.com/soos-io/soos-dast#scan-modes) |
| `--timeout` |  | Max time in minutes to wait for ZAP to start and the passive scan to run |

## Scan Modes

### Baseline

It runs the [ZAP](https://www.zaproxy.org/docs/docker/about/) spider against the specified target for (by default) 1 minute and then waits for the passive scanning to complete before reporting the results.

This means that the CLI doesn't perform any actual ‘attacks’ and will run for a relatively short period of time (a few minutes at most).

By default, it reports all alerts as WARNings but you can specify a config file which can change any rules to `FAIL` or `IGNORE`.

This mode is intended to be ideal to run in a `CI/CD` environment, even against production sites.

### Full Scan

It runs the [ZAP](https://www.zaproxy.org/docs/docker/about/) spider against the specified target (by default with no time limit) followed by an optional ajax spider scan and then a full `Active Scan` before reporting the results.

This means that the CLI does perform actual ‘attacks’ and can potentially run for a long period of time. You should NOT use it on web applications that you do not own. `Active Scan` can only find certain types of vulnerabilities. Logical vulnerabilities, such as broken access control, will not be found by any active or automated vulnerability scanning. Manual penetration testing should always be performed in addition to active scanning to find all types of vulnerabilities.

By default, it reports all alerts as WARNings but you can specify a config file which can change any rules to FAIL or IGNORE. The configuration works in a very similar way as the [Baseline Mode](#baseline)

### API Scan

It is tuned for performing scans against APIs defined by `openapi`, `soap`, or `graphql` via either a local file or a URL.

To point to a local file, use the following syntax:
```
docker run -u zap -v <absolute-path-to-local-file>:/zap/wrk/:rw -it --rm soosio/dast --clientId=<client>--apiKey=<apiKey> --projectName=<api project name> --scanMode=apiscan --apiScanFormat=openapi swagger.yaml
```
*NOTE:* the zap user (1000:1000) will need rwx access to the mount. If you can't do that, you can run as without the -u parameter and have the container run as root.

Be sure the local file still points to the live endpoint of your API. E.g. for `openapi` YAML, you would set the `servers` section:
```
servers:
  - url: https://myapi.example.com
```

NOTE: The DNS name of the API being scanned must be resolved by the Docker container. Use an IP address if this is not possible.

It imports the definition that you specify and then runs an `Active Scan` against the URLs found. The `Active Scan` is tuned to APIs, so it doesn't bother looking for things like `XSSs`.

It also includes 2 example scripts that:
- Raise alerts for any HTTP Server Error response codes
- Raise alerts for any URLs that return content types that are not usually associated with APIs

## References
 - [ZAP](https://www.zaproxy.org/)
 - [Docker](https://docs.docker.com/)


### Notes
Be sure to use the public registry for installation of NPM packages:
 `npm install --registry https://registry.npmjs.org/` 

Be sure to wait for all actions to finish before tagging, releasing etc.
