FROM zaproxy/zap-weekly:20240722 as base

USER root

# Install nodejs version based on NODE_MAJOR
ENV NODE_MAJOR 18
RUN apt-get update
RUN apt-get install -y ca-certificates curl gnupg
RUN mkdir -p /etc/apt/keyrings
RUN curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
RUN echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list
RUN apt-get update
RUN apt-get install -y nodejs

COPY ./src/ ./src/
COPY ./tsconfig.json ./
COPY ./package.json ./

RUN pip3 install -r ./src/zap_hooks/requirements.txt

RUN mkdir /zap/wrk && cd /opt \
    && wget -qO- -O geckodriver.tar.gz https://github.com/mozilla/geckodriver/releases/download/v0.30.0/geckodriver-v0.30.0-linux64.tar.gz \
    && tar -xvzf geckodriver.tar.gz \
    && chmod +x geckodriver \
    && ln -s /opt/geckodriver /usr/bin/geckodriver \
    && export PATH=$PATH:/usr/bin/geckodriver

# Set up Chrome version to be used
ARG CHROME_VERSION="125.0.6422.141-1"

# Set up the Chrome PPA
RUN wget --no-verbose -O /tmp/chrome.deb https://dl.google.com/linux/deb/pool/main/g/google-chrome-stable/google-chrome-stable_${CHROME_VERSION}_amd64.deb \ 
  && apt-get update \
  && apt install -y /tmp/chrome.deb \
  && rm /tmp/chrome.deb

# Set up Chromedriver Environment variables
ENV CHROMEDRIVER_VERSION 125.0.6422.141
ENV CHROMEDRIVER_DIR /chromedriver
RUN mkdir $CHROMEDRIVER_DIR

# Download and install Chromedriver
RUN wget -q --continue -P $CHROMEDRIVER_DIR "https://storage.googleapis.com/chrome-for-testing-public/$CHROMEDRIVER_VERSION/linux64/chrome-linux64.zip"
RUN unzip $CHROMEDRIVER_DIR/chrome-linux64.zip -d $CHROMEDRIVER_DIR

# Put Chromedriver into the PATH
ENV PATH $CHROMEDRIVER_DIR:$PATH

COPY ./src/reports/traditional-json /zap/reports/traditional-json
RUN chmod -R 444 /zap/reports/traditional-json

RUN npm install

RUN npm run build

ENTRYPOINT ["node", "--no-deprecation", "dist/index.js"]
