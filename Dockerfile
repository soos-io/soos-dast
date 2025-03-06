FROM zaproxy/zap-stable:2.16.0 AS base

USER root

# Install nodejs
RUN apt-get update
RUN apt-get install -y ca-certificates curl gnupg
RUN mkdir -p /etc/apt/keyrings
RUN curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
RUN echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list
RUN apt-get update
RUN apt-get install -y nodejs
RUN apt-get install -y python3-requests python3-termcolor python3-selenium python3-pyotp python3-blinker

COPY ./src/ ./src/
COPY ./tsconfig.json ./
COPY ./package.json ./

RUN mkdir /zap/wrk && cd /opt \
    && wget -qO- -O geckodriver.tar.gz https://github.com/mozilla/geckodriver/releases/download/v0.36.0/geckodriver-v0.36.0-linux64.tar.gz \
    && tar -xvzf geckodriver.tar.gz \
    && chmod +x geckodriver \
    && ln -s /opt/geckodriver /usr/bin/geckodriver \
    && export PATH=$PATH:/usr/bin/geckodriver

# Set up the Chrome PPA - https://chromereleases.googleblog.com/search/label/Stable%20updates
RUN wget --no-verbose -O /tmp/chrome.deb https://dl.google.com/linux/deb/pool/main/g/google-chrome-stable/google-chrome-stable_134.0.6998.35-1_amd64.deb \ 
  && apt-get update \
  && apt install -y /tmp/chrome.deb \
  && rm /tmp/chrome.deb

# Set up Chromedriver
ENV CHROMEDRIVER_DIR /chromedriver
RUN mkdir $CHROMEDRIVER_DIR
RUN wget -q --continue -P $CHROMEDRIVER_DIR "https://storage.googleapis.com/chrome-for-testing-public/134.0.6998.35/linux64/chrome-linux64.zip"
RUN unzip $CHROMEDRIVER_DIR/chrome-linux64.zip -d $CHROMEDRIVER_DIR
ENV PATH $CHROMEDRIVER_DIR:$PATH

COPY ./src/reports/traditional-json /zap/reports/traditional-json
RUN chmod -R 444 /zap/reports/traditional-json

RUN npm install

RUN npm run build

ENTRYPOINT ["node", "--no-deprecation", "dist/index.js"]
