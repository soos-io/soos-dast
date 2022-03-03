# SOOS-DAST-Python

## DAST Analysis Tool
A **Dynamic Analysis Security Testing**, or **DAST**, tool is a security solution application that can help find certain vulnerabilities in web applications while they are running in production.

The **SOOS-DAST-Python** is the **DAST** solution provided by **SOOS** (Supported by [OWASP ZAP](https://owasp.org/www-project-zap/)) to get the analysis results for your web applications into the **SOOS** Application.

## Requirements
- [Docker](https://www.docker.com/get-started)
- Have your application or website reachable on some URL.  

## How to Use
To execute the script you need to run this command from a terminal:
``` shell
docker run -it --rm soosio/dast [--configFile CONFIGFILE] [--clientId CLIENTID]
               [--apiKey APIKEY] [--projectName PROJECTNAME]
               [--scanMode SCANMODE] [--apiURL APIURL] [--debug DEBUG]
               [--ajaxSpider AJAXSPIDER] [--rules RULES]
               [--contextFile CONTEXTFILE] [--contextUser CONTEXTUSER]
               [--fullScanMinutes FULLSCANMINUTES]
               [--apiScanFormat APISCANFORMAT] [--level LEVEL]
               [--integrationName INTEGRATIONNAME] [--authDisplay AUTHDISPLAY]
               [--authUsername AUTHUSERNAME] [--authPassword AUTHPASSWORD]
               [--authLoginURL AUTHLOGINURL]
               [--authUsernameField AUTHUSERNAMEFIELD]
               [--authPasswordField AUTHPASSWORDFIELD]
               [--authSubmitField AUTHSUBMITFIELD]
               [--authFirstSubmitField AUTHFIRSTSUBMITFIELD]
               [--zapOptions ZAPOPTIONS] [--requestCookies REQUESTCOOKIES]
               [--requestHeader REQUESTHEADER] [--commitHash COMMITHASH]
               [--branchName BRANCHNAME] [--branchURI BRANCHURI]
               [--buildVersion BUILDVERSION] [--buildURI BUILDURI]
               [--operatingEnvironment OPERATINGENVIRONMENT]
               targetURL
```

### Script Arguments

| Name        | Required | Description                                                   |
|-------------|----------|---------------------------------------------------------------|
| `targetURL` | Yes      | target URL including the protocol, eg https://www.example.com |

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
| `requestCookies`                           |                                            | add custom cookies to the requests                                                                               |
| `requestHeaders`                           |                                            | add custom headers to the requests                                                                               |


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
