# Stack-Aware

## A DAST Analysis Tool
A **Dynamic Analysis Security Testing**, or **DAST**, tool is an application security solution that can help to find certain vulnerabilities in web applications while they are running in production.

The **Stack-Aware** is the **DAST** solution provided by **SOOS** (Supported by [OWASP ZAP](https://owasp.org/www-project-zap/)) to get the analysis results for your web applications into the **SOOS** Application.

## Requirements
- Install [Docker](https://www.docker.com/get-started)
- Have your application or website reachable on some URL.  

## How to Usage
### Create a config file
Create a config yaml file following this template:
``` yaml
config:
  clientId: 'SOOS_CLIENT_ID' # Required - SOOS Client Id provided by the Application
  apiKey: 'SOOS_API_KEY' # Required - SOOS API Key provided by the Application
  projectName: 'Project Name' # Required
  scanMode: 'activescan' # Required - DAST Scan mode. Values availables: baseline, fullscan, apiscan, and activescan
  apiURL: 'https://app.soos.io/api/' # Required - The SOOS API URL
  targetUrl: 'https://example.com' # Required - The target url to be analyzed
  debug: true # Optional - Enable console log debugging. Default: false 
  ajaxSpider: false # Optional - Enable Ajax Spider scanning - Useful for Modern Web Apps
  rules: '' # Optional - 
  context:
    file: '' # Optional
    user: '' # Opitonal
  fullScan:
    minutes: ''
  apiScan:
    format: 'openapi'
  activeScan:
    level: 'low'
```

### Pull the docker image
From a terminal pull the SOOS DAST Docker image running the command:
``` shell
docker pull soos/dast-analysis:1.0.0
``` 

### Run the docker image
``` shell
docker run docker run -i -t --rm -v <config file path>:/zap/config.yml soos/dast-analysis:1.0.0
```

## Build the image
From the same location as the Dockerfile, build the image.
<br>
*Note: In order to change the configuration you will need to re-run this command or run this command with a different tag.*

`docker-compose build`

## Create a container, run the scan
Using the image we just built, create a detached container and run the scan.

`docker-compose run app`

## Copy the scan report to a local file
After the scan as been run, copy the report to a local file.

`docker cp stack-aware:zap/wrk/report.json report.json`

## Remove the container
`docker container rm stack-aware`

## Remove the image
`docker image rm stack-aware:latest`
