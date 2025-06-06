FROM zaproxy/zap-stable:2.16.1 AS base

USER root

# Install nodejs
RUN apt-get update
RUN apt-get install -y ca-certificates curl gnupg
RUN mkdir -p /etc/apt/keyrings
RUN curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
RUN echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list
RUN apt-get update
RUN apt-get install -y nodejs
RUN apt-get install -y python3-requests python3-termcolor python3-selenium python3-blinker

COPY ./src/ ./src/
COPY ./tsconfig.json ./
COPY ./package.json ./
COPY ./package-lock.json ./

# The default working directory
RUN mkdir /zap/wrk

# Set up Chrome - Check here for newer version numbers https://deb.pkgs.org/packages/google-amd64/
RUN wget --no-verbose -O /tmp/chrome.deb https://dl.google.com/linux/deb/pool/main/g/google-chrome-stable/google-chrome-stable_137.0.7151.68-1_amd64.deb \ 
  && apt-get update \
  && apt install -y /tmp/chrome.deb \
  && rm /tmp/chrome.deb

COPY ./src/reports/traditional-json /zap/reports/traditional-json
RUN chmod -R 444 /zap/reports/traditional-json

RUN npm ci
RUN npm run build

ENTRYPOINT ["node", "--no-deprecation", "dist/index.js"]
