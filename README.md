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
docker run -it --rm soosio/dast [--configFile CONFIGFILE] [--clientId CLIENTID] [--apiKey APIKEY] [--projectName PROJECTNAME [PROJECTNAME ...]]
               [--scanMode SCANMODE] [--apiURL APIURL] [--debug DEBUG] [--ajaxSpider AJAXSPIDER] [--rules [RULES [RULES ...]]]
               [--contextFile [CONTEXTFILE [CONTEXTFILE ...]]] [--contextUser [CONTEXTUSER [CONTEXTUSER ...]]] [--fullScanMinutes FULLSCANMINUTES]
               [--apiScanFormat APISCANFORMAT] [--level LEVEL] [--integrationName [INTEGRATIONNAME [INTEGRATIONNAME ...]]] [--authDisplay AUTHDISPLAY]
               [--authUsername AUTHUSERNAME] [--authPassword AUTHPASSWORD] [--authLoginURL AUTHLOGINURL] [--authUsernameField AUTHUSERNAMEFIELD]
               [--authPasswordField AUTHPASSWORDFIELD] [--authSubmitField AUTHSUBMITFIELD] [--authFirstSubmitField AUTHFIRSTSUBMITFIELD]
               [--bearerToken BEARERTOKEN] [--zapOptions [ZAPOPTIONS [ZAPOPTIONS ...]]] [--requestCookies [REQUESTCOOKIES [REQUESTCOOKIES ...]]]
               [--requestHeader [REQUESTHEADER [REQUESTHEADER ...]]] [--commitHash COMMITHASH] [--branchName [BRANCHNAME [BRANCHNAME ...]]]
               [--branchURI BRANCHURI] [--buildVersion BUILDVERSION] [--buildURI BUILDURI]
               [--operatingEnvironment [OPERATINGENVIRONMENT [OPERATINGENVIRONMENT ...]]] [--sarif SARIF] [--gpat GPAT]
               targetURL
```

### Script Arguments

| Name        | Required | Description                                                                                   |
|-------------|----------|-----------------------------------------------------------------------------------------------|
| `targetURL` | Yes      | target URL including the protocol, eg https://www.example.com. A `https` protocol is required |

### Script Parameters

| Name                                       | Required                                   | Description                                                                                                      |
|--------------------------------------------|--------------------------------------------|------------------------------------------------------------------------------------------------------------------|
| `configFile`                               |                                            | SOOS YAML file with all the configurations for the DAST Analysis. See [config file definition](#config-file-definition) |
| `-v <path_with_config_files>:/zap/config/` | Yes - if `configFile` param is defined     |                                                                                                                  |
| `clientId`                                 | Yes - if `configFile` param is not defined | SOOS client id                                                                                                   |
| `apiKey`                                   | Yes - if `configFile` param is not defined | SOOS API key                                                                                                     |
| `projectName`                              | Yes - if `configFile` param is not defined | SOOS project name                                                                                                |
| `scanMode`                                 | Yes - if `configFile` param is not defined | SOOS DAST scan mode. Values: `baseline` (Default), `fullscan`, `apiscan`, or `activescan`                        |
| `apiURL`                                   | Yes - if `configFile` param is not defined | SOOS API URL. By Default: `https://app.soos.io/api/`                                                             |
| `debug`                                    |                                            | show debug messages                                                                                              |
| `ajaxSpider`                               |                                            | use the Ajax spider in addition to the traditional one                                                           |
| `rules`                                    |                                            | rules file to use for `INFO`, `IGNORE` or `FAIL` warnings                                                        |
| `contextFile`                              |                                            | context file which will be loaded prior to scanning the target. Required for authenticated URLs                  |
| `contextUser`                              |                                            | username to use for authenticated scans - must be defined in the given context file                              |
| `fullScanMinutes`                          | Yes - if `scanMode` is `fullscan`          | the number of minutes for spider to run                                                                          |
| `apiScanFormat`                            | Yes - if `scanMode` is `apiscan`           | target API format: `openapi`, `soap`, or `graphql`                                                               |
| `level`                                    |                                            | minimum level to show: `PASS`, `IGNORE`, `INFO`, `WARN` or `FAIL`                                                |
| `zapOptions`                               |                                            | add zap options                                                                                                  |
| `requestCookies`                           |                                            | comma separated list of custom cookies to be added to the request eg: `--requestCookies="'token: value, user: usernName'"`                                                                               |
| `requestHeader`                           |                                            | custom header to be sent on every request eg:  `--requestHeader="'authorization:Bearer tokenValue'"`                                                                               |
| `commitHash`                      | [none]                     | The commit hash value from the SCM System. Required for SARIF Report                                                                                                                                                                          |
| `branchName`                      | [none]                     | The name of the branch from the SCM System. Required for SARIF Report                                                                                                                                                                         |
| `branchURI`                       | [none]                     | The URI to the branch from the SCM System                                                                                                                                                                                                    |
| `buildVersion`                    | [none]                     | Version of application build artifacts                                                                                                                                                                                                        |
| `buildURI`                        | [none]                     | URI to CI build info                                                                                                                                                                                                                          |
| `operatingEnvironment`            | [none]                     | System info regarding operating system, etc.                                                                                                                                                                                                  |
| `sarif`                            | false                      | Enable Uploading the SARIF Report to GitHub.                                                                                                                                                                                                  |
| `gpat`                             | [none]                     | GitHub Personal Access Token. Required to upload SARIF Report                                                                                                                                                                                |
| `bearerToken`                             | [none]                     | A Bearer token to use in the authorization header for each request. (Do not include Bearer Keyword on parameter)                                                                                                          |
| `authLoginUrl`                             | [none]                     | Url to perform automatic login request.                                                                                                          |
| `authUserName`                             | [none]                     | Username to fill automatic login.                                                                                                           |
| `authUserNameField`                             | [none]                     | The HTML name or id attribute of the username field.                                                                                                          |
| `authPassword`                             | [none]                     | Password to fill automatic login.                                                                                                          |
| `authPasswordField`                             | [none]                     | The HTML name or id attribute of the password field.                                                                                                          |
| `authSubmitField`                             | [none]                     | The HTML name or id attribute of the submit field.                                                                                                        |
| `authSubmitAction`                             | [none]                     | Default action to perform on form completion (click or submit, click is by default)                                                                                                          |



#### Config File Definition
``` yaml
config:
  clientId: 'SOOS_CLIENT_ID' # Required - SOOS Client Id provided by the Application
  apiKey: 'SOOS_API_KEY' # Required - SOOS API Key provided by the Application
  projectName: 'Project Name' # Required
  scanMode: 'activescan' # Required - DAST Scan mode. Values available: baseline, fullscan, apiscan, and activescan
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

It runs the [ZAP](https://www.zaproxy.org/) spider against the specified target (by default with no time limit) followed by an optional ajax spider scan and then a full active scan before reporting the results.

This means that the script does perform actual ‘attacks’ and can potentially run for a long period of time.

By default, it reports all alerts as WARNings but you can specify a config file which can change any rules to FAIL or IGNORE. The configuration works in a very similar way as the [Baseline Mode](#baseline)

### API Scan

It is tuned for performing scans against APIs defined by `OpenAPI`, `SOAP`, or `GraphQL` via either a local file or a URL.

It imports the definition that you specify and then runs an `Active Scan` against the URLs found. The `Active Scan` is tuned to APIs, so it doesn't bother looking for things like `XSSs`.

It also includes 2 scripts that:
- Raise alerts for any HTTP Server Error response codes
- Raise alerts for any URLs that return content types that are not usually associated with APIs

### Active Scan

It attempts to find potential vulnerabilities by using known attacks against the selected targets. `Active Scan` is an attack on those targets. You should NOT use it on web applications that you do not own.

`Active Scan` can only find certain types of vulnerabilities.

Logical vulnerabilities, such as broken access control, will not be found by any active or automated vulnerability scanning.

Manual penetration testing should always be performed in addition to active scanning to find all types of vulnerabilities.

## References
 - [ZAP](https://www.zaproxy.org/)
