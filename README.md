# [SOOS DAST](https://soos.io/dast-product/)

SOOS is an independent software security company, located in Winooski, VT USA, building security software for your team. [SOOS, Software security, simplified](https://soos.io).

Use SOOS to scan your software for [vulnerabilities](https://app.soos.io/research/vulnerabilities) and [open source license](https://app.soos.io/research/licenses) issues with [SOOS Core SCA](https://soos.io/sca-product). [Generate SBOMs](https://kb.soos.io/help/generating-a-software-bill-of-materials-sbom). Govern your open source dependencies. Run the [SOOS DAST vulnerability scanner](https://soos.io/dast-product) against your web apps or APIs.

[Demo SOOS](https://app.soos.io/demo) or [Register for a Free Trial](https://app.soos.io/register).

If you maintain an Open Source project, sign up for the Free as in Beer [SOOS Community Edition](https://soos.io/products/community-edition).

## Requirements
- [Docker](https://www.docker.com/get-started)
- Have your application or website reachable via URL.

## How to Use
To start the scan you need to run this command from a terminal:
``` shell
docker run -it --rm soosio/dast <parameters>
```

The basic command to run a baseline scan would look like:
`docker run -it --rm soosio/dast --clientId=<YOUR_CLIENT_ID> --apiKey=<YOUR_API_KEY> --projectName="<YOUR_PROJECT_NAME>" <YOUR_TARGET_URL>`

### Arguments

| Argument | Required | Description |
| --- | --- | --- |
| `targetURL` | Yes | Target URL - URL of the site or api to scan. The URL should include the protocol. Ex: https://www.example.com |

### Parameters

| Argument | Default | Description |
| --- | --- | --- |
| `--ajaxSpider` | None | Ajax Spider - Use the ajax spider in addition to the traditional one. Additional information: https://www.zaproxy.org/docs/desktop/addons/ajax-spider/ |
| `--apiKey` | None | SOOS API Key - get yours from https://app.soos.io/integrate/dast |
| `--appVersion` | N/A | App Version - Intended for internal use only. |
| `--authDelayTime` | 5 | Delay time in seconds to wait for the page to load after performing actions in the form. (Used only on authFormType: wait_for_password and multi_page) |
| `--authFormType` | simple | simple (all fields are displayed at once), wait_for_password (Password field is displayed only after username is filled), or multi_page (Password field is displayed only after username is filled and submit is clicked) |
| `--authLoginURL` | None | Login url to use when authentication is required |
| `--authPassword` | None | Password to use when authentication is required |
| `--authPasswordField` | None | Password input id to use when authentication is required |
| `--authSecondSubmitField` | None | Second submit button id to use when authentication is required (for multi-page forms) |
| `--authSubmitAction` | None | Submit action to perform on form filled. Options: click or submit |
| `--authSubmitField` | None | Submit button id to use when authentication is required |
| `--authUsername` | None | Username to use when authentication is required |
| `--authUsernameField` | None | Username input id to use when authentication is required |
| `--authVerificationURL` | None | URL used to verify authentication success, should be an URL that is expected to throw 200/302 during any authFormType authentication. If authentication fails when this URL is provided, the scan will be terminated. |
| `--bearerToken` | None | Bearer token to authenticate |
| `--branchName` | None | The name of the branch from the SCM System |
| `--branchURI` | None | The URI to the branch from the SCM System |
| `--buildURI` | None | URI to CI build info |
| `--buildVersion` | None | Version of application build artifacts |
| `--checkoutDir` | None | Checkout directory to locate SARIF report |
| `--clientId` | None | SOOS Client ID - get yours from https://app.soos.io/integrate/dast |
| `--commitHash` | None | The commit hash value from the SCM System |
| `--contextFile` | None | Context file which will be loaded prior to scanning the target |
| `--debug` | False | Enable debug logging for ZAP. |
| `--disableRules` | None | Comma separated list of ZAP rules IDs to disable. List for reference https://www.zaproxy.org/docs/alerts/ |
| `--fullScanMinutes` | None | Number of minutes for the spider to run |
| `--help`, `-h` | ==SUPPRESS== | show this help message and exit |
| `--integrationName` | N/A | Integration Name - Intended for internal use only. |
| `--integrationType` | N/A | Integration Type - Intended for internal use only. |
| `--logLevel` | None | Minimum level to show logs: PASS, IGNORE, INFO, WARN, FAIL, DEBUG, ERROR. |
| `--oauthParameters` | None | Parameters to be added to the oauth token request. (eg --oauthParameters="client_id:clientID, client_secret:clientSecret, grant_type:client_credentials") |
| `--oauthTokenUrl` | None | The authentication URL that grants the access_token. |
| `--onFailure` | continue_on_failure | Action to perform when the scan fails. Options: fail_the_build, continue_on_failure |
| `--operatingEnvironment` | None | Set Operating environment for information purposes only |
| `--otherOptions` | None | Additional command line arguments for items not supported by the set of parameters above |
| `--outputFormat` | None | Output format for vulnerabilities: only the value SARIF is available at the moment |
| `--projectName` | None | Project Name - this is what will be displayed in the SOOS app |
| `--requestCookies` | None | Set Cookie values for the requests to the target URL |
| `--requestHeaders` | None | Set extra Header requests |
| `--scanMode` | baseline | Scan Mode - Available modes: baseline, fullscan, and apiscan (for more information about scan modes visit https://github.com/soos-io/soos-dast#scan-modes) |
| `--scriptVersion` | N/A | Script Version - Intended for internal use only. |

## Scan Modes

### Baseline

It runs the [ZAP](https://www.zaproxy.org/docs/docker/about/) spider against the specified target for (by default) 1 minute and then waits for the passive scanning to complete before reporting the results.

This means that the script doesn't perform any actual ‘attacks’ and will run for a relatively short period of time (a few minutes at most).

By default, it reports all alerts as WARNings but you can specify a config file which can change any rules to `FAIL` or `IGNORE`.

This mode is intended to be ideal to run in a `CI/CD` environment, even against production sites.

### Full Scan

It runs the [ZAP](https://www.zaproxy.org/docs/docker/about/) spider against the specified target (by default with no time limit) followed by an optional ajax spider scan and then a full `Active Scan` before reporting the results.

This means that the script does perform actual ‘attacks’ and can potentially run for a long period of time. You should NOT use it on web applications that you do not own. `Active Scan` can only find certain types of vulnerabilities. Logical vulnerabilities, such as broken access control, will not be found by any active or automated vulnerability scanning. Manual penetration testing should always be performed in addition to active scanning to find all types of vulnerabilities.

By default, it reports all alerts as WARNings but you can specify a config file which can change any rules to FAIL or IGNORE. The configuration works in a very similar way as the [Baseline Mode](#baseline)

### API Scan

It is tuned for performing scans against APIs defined by `openapi`, `soap`, or `graphql` via either a local file or a URL.

To point to a local file, use the following syntax:
```
docker run -v <absolute-path-to-local-file>:/zap/wrk/:rw -it --rm soosio/dast --clientId=<client>--apiKey=<apiKey> --projectName=<api project name> --scanMode=apiscan --apiScanFormat=openapi swagger.yaml
```

Be sure the local file still points to the live endpoint of your API. E.g. for `openapi` YAML, you would set the `servers` section:
```
servers:
  - url: https://myapi.example.com
```

NOTE: The DNS name of the API being scanned must be resolved by the Docker container. Use an IP address if this is not possible.

It imports the definition that you specify and then runs an `Active Scan` against the URLs found. The `Active Scan` is tuned to APIs, so it doesn't bother looking for things like `XSSs`.

It also includes 2 scripts that:
- Raise alerts for any HTTP Server Error response codes
- Raise alerts for any URLs that return content types that are not usually associated with APIs

## References
 - [ZAP](https://www.zaproxy.org/)
 - [Docker](https://docs.docker.com/)
