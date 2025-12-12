FROM zaproxy/zap-stable:2.16.1 AS base

USER root

RUN apt-get update && apt-get install -y ca-certificates curl gnupg
RUN mkdir -p /etc/apt/keyrings
RUN curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
RUN echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_24.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list
RUN apt-get update && apt-get install -y nodejs
RUN apt-get install -y python3-termcolor python3-selenium python3-blinker

# Set up Chrome - Check here for newer version numbers https://pkgs.org/download/google-chrome-stable
RUN wget --no-verbose -O /tmp/chrome.deb https://dl.google.com/linux/deb/pool/main/g/google-chrome-stable/google-chrome-stable_143.0.7499.109-1_amd64.deb \
  && apt-get update \
  && apt install -y /tmp/chrome.deb \
  && rm /tmp/chrome.deb

COPY --chown=zap:zap ./src/ ./src/
COPY ./tsconfig.json ./
COPY ./package.json ./
COPY ./package-lock.json ./
RUN npm ci && npm run build

COPY --chown=zap:zap ./src/reports/traditional-json/report.json /zap/reports/traditional-json/report.json
RUN mkdir -p /zap/wrk && chown -R zap:zap /zap/wrk && chmod -R 770 /zap/wrk

ENTRYPOINT ["node", "--no-deprecation", "dist/index.js"]
