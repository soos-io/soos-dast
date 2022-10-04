# SOOS-DAST-Python

## DAST Analysis Tool
The affordable no limit web vulnerability scanner.

Use **SOOS DAST** to:

1. Scan web apps and APIs defined by **OpenAPI**, **SOAP**, or **GraphQL**
2. Containerized solution runs in your environment
3. Manage issues via single-pane web dashboard shared with [SOOS SCA](https://github.com/marketplace/actions/soos-sca-github-action)
4. Track tickets in Jira or GitHub Issues

## Requirements
- [Docker](https://www.docker.com/get-started)
- Have your application or website reachable on some URL.  

## How to Use
To execute the script you need to run this command from a terminal:
``` shell
docker run -it --rm soosio/dast <parameters>
```

The basic command to run a baseline scan would look like:

`docker run -it --rm soosio/dast --clientId=<YOUR_CLIENTID> --apiKey=<YOUR_APIKEY> --projectName="<YOUR_PROJECT_NAME>" <YOUR_TARGET_URL>`
### Script Arguments

| Name        | Required | Description                                                                                   |
|-------------|----------|-----------------------------------------------------------------------------------------------|
| `targetURL` | Yes      | target URL including the protocol, eg https://www.example.com. A `https` protocol is required |

### Script Parameters

| Argument | Default | Description |
| --- | --- | --- |
| -h, --help | ==SUPPRESS== | show this help message and exit |
| -hf, --helpFormatted | False | Print the --help command in markdown table format |
| --configFile | None | SOOS yaml file with all the configuration for the DAST Analysis (See https://github.com/soos-io/soos-dast#config-file-definition) |
| --clientId | None | SOOS Client ID get yours from https://app.soos.io/integrate/sca |
| --apiKey | None | SOOS API Key get yours from https://app.soos.io/integrate/sca |
| --projectName | None | Project name (this will be the one used inside of the SOOS App) |
| --scanMode | baseline | SOOS DAST scan mode. Values available: baseline, fullscan, and apiscan (for more information about scan modes visit https://github.com/soos-io/soos-dast#scan-modes) |
| --apiURL | https://api.soos.io/api/ | SOOS API URL, internal use only, do not modify. |
| --debug | False | Show debug messages |
| --ajaxSpider | None | Use the Ajax spider in addition to the traditional one (About AjaxSpider https://www.zaproxy.org/docs/desktop/addons/ajax-spider/) |
| --rules | None | Rules file to use to INFO, IGNORE or FAIL warnings |
| --contextFile | None | Context file which will be loaded prior to scanning the target |
| --contextUser | None | Username to use for authenticated scans - must be defined in the given context file |
| --fullScanMinutes | None | The number of minutes for spider to run |
| --apiScanFormat | None | Target API format: openapi, soap, or graphql |
| --level | None | minimum level to show: PASS, IGNORE, INFO, WARN or FAIL |
| --integrationName | None | Integration Name. Intended for internal use only. |
| --integrationType | None | Integration Type. Intended for internal use only. |
| --scriptVersion | None | Script Version. Intended for internal use only. |
| --appVersion | None | App Version. Intended for internal use only. |
| --authDisplay | None | Minimum level to show: PASS, IGNORE, INFO, WARN or FAIL |
| --authUsername | None | Username to use in auth apps |
| --authPassword | None | Password to use in auth apps |
| --authLoginURL | None | Login url to use in auth apps |
| --authUsernameField | None | Username input id to use in auth apps |
| --authPasswordField | None | Password input id to use in auth apps |
| --authSubmitField | None | Submit button id to use in auth apps |
| --authFirstSubmitField | None | First submit button id to use in auth apps |
| --authSubmitAction | None | Submit action to perform on form filled, click or submit |
| --zapOptions | None | ZAP Additional Options |
| --requestCookies | None | Set Cookie values for the requests to the target URL |
| --requestHeaders | None | Set extra Header requests |
| --commitHash | None | The commit hash value from the SCM System |
| --branchName | None | The name of the branch from the SCM System |
| --branchURI | None | The URI to the branch from the SCM System |
| --buildVersion | None | Version of application build artifacts |
| --buildURI | None | URI to CI build info |
| --operatingEnvironment | None | Set Operating environment for information porpuses only |
| --reportRequestHeaders | True | Include request/response headers data in report |
| --outputFormat | None | Output format for vulnerabilities: only the value sarif is available at the moment |
| --gpat | None | GitHub Personal Authorization Token |
| --bearerToken | None | Bearer token to authenticate |
| --checkoutDir | None | Checkout Dir to locate sarif report |
| --sarifDestination | None | Sarif destination to upload report in the form of <repoowner>/<reponame> |
| --sarif | None | DEPRECATED sarif parameter is currently deprecated, for same functionality as before please use --outPutFormat='sarif' |
| --oauthTokenUrl | None | The fully qualified authentication URL that grants the access_token. |
| --oauthParameters | None | Parameters to be added to the oauth token request. (eg --oauthParameters="client_id:clientID, client_secret:clientSecret, grant_type:client_credentials") |



#### Config File Definition
``` yaml
config:
  clientId: 'SOOS_CLIENT_ID' # Required - SOOS Client Id provided by the Application
  apiKey: 'SOOS_API_KEY' # Required - SOOS API Key provided by the Application
  projectName: 'Project Name' # Required
  scanMode: 'baseline' # Required - DAST Scan mode. Values available: baseline, fullscan, and apiscan
  apiURL: 'https://app.soos.io/api/' # Required - The SOOS API URL
  debug: true # Optional - Enable console log debugging. Default: false 
  ajaxSpider: false # Optional - Enable Ajax Spider scanning - Useful for Modern Web Apps
  rules: '' # Optional - 
  context:
    file: '' # Optional
    user: '' # Optional
  fullScan:
    minutes: ''
  apiScan:
    format: 'openapi'
  level: 'PASS'
```

## Scan Modes

### Baseline

It runs the [ZAP](https://www.zaproxy.org/) spider against the specified target for (by default) 1 minute and then waits for the passive scanning to complete before reporting the results.

This means that the script doesn't perform any actual ‘attacks’ and will run for a relatively short period of time (a few minutes at most).

By default, it reports all alerts as WARNings but you can specify a config file which can change any rules to `FAIL` or `IGNORE`.

This mode is intended to be ideal to run in a `CI/CD` environment, even against production sites.

### Full Scan

It runs the [ZAP](https://www.zaproxy.org/) spider against the specified target (by default with no time limit) followed by an optional ajax spider scan and then a full `Active Scan` before reporting the results.

This means that the script does perform actual ‘attacks’ and can potentially run for a long period of time. You should NOT use it on web applications that you do not own. `Active Scan` can only find certain types of vulnerabilities. Logical vulnerabilities, such as broken access control, will not be found by any active or automated vulnerability scanning. Manual penetration testing should always be performed in addition to active scanning to find all types of vulnerabilities.

By default, it reports all alerts as WARNings but you can specify a config file which can change any rules to FAIL or IGNORE. The configuration works in a very similar way as the [Baseline Mode](#baseline)

### API Scan

It is tuned for performing scans against APIs defined by `openapi`, `soap`, or `graphql` via either a local file or a URL.

It imports the definition that you specify and then runs an `Active Scan` against the URLs found. The `Active Scan` is tuned to APIs, so it doesn't bother looking for things like `XSSs`.

It also includes 2 scripts that:
- Raise alerts for any HTTP Server Error response codes
- Raise alerts for any URLs that return content types that are not usually associated with APIs

## References
 - [ZAP](https://www.zaproxy.org/)
