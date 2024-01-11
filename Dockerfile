FROM soosio/zap2docker-soos as base

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

RUN cd /zap/plugin && \
	rm -rf ascanrules-* && wget https://github.com/zaproxy/zap-extensions/releases/download/ascanrules-v49/ascanrules-release-49.zap && \
    rm -rf ascanrulesBeta-* && wget https://github.com/zaproxy/zap-extensions/releases/download/ascanrulesBeta-v44/ascanrulesBeta-beta-44.zap && \
	rm -rf commonlib-* && wget https://github.com/zaproxy/zap-extensions/releases/download/commonlib-v1.12.0/commonlib-release-1.12.0.zap && \
	rm -rf network-* && wget https://github.com/zaproxy/zap-extensions/releases/download/network-v0.6.0/network-beta-0.6.0.zap && \
	rm -rf oast-* && wget https://github.com/zaproxy/zap-extensions/releases/download/oast-v0.14.0/oast-beta-0.14.0.zap && \
	rm -rf pscanrules-* && wget https://github.com/zaproxy/zap-extensions/releases/download/pscanrules-v44/pscanrules-release-44.zap && \
    rm -rf pscanrulesBeta-* && wget https://github.com/zaproxy/zap-extensions/releases/download/pscanrulesBeta-v31/pscanrulesBeta-beta-31.zap && \
	chown -R zap:zap /zap

# Set up Chrome version to be used
ARG CHROME_VERSION="114.0.5735.133-1"

# Set up the Chrome PPA
RUN wget --no-verbose -O /tmp/chrome.deb https://dl.google.com/linux/chrome/deb/pool/main/g/google-chrome-stable/google-chrome-stable_${CHROME_VERSION}_amd64.deb \ 
  && apt-get update \
  && apt install -y /tmp/chrome.deb \
  && rm /tmp/chrome.deb

# Set up Chromedriver Environment variables
ENV CHROMEDRIVER_VERSION 114.0.5735.16
ENV CHROMEDRIVER_DIR /chromedriver
RUN mkdir $CHROMEDRIVER_DIR

# Download and install Chromedriver
RUN wget -q --continue -P $CHROMEDRIVER_DIR "https://chromedriver.storage.googleapis.com/$CHROMEDRIVER_VERSION/chromedriver_linux64.zip"
RUN unzip $CHROMEDRIVER_DIR/chromedriver* -d $CHROMEDRIVER_DIR

# Put Chromedriver into the PATH
ENV PATH $CHROMEDRIVER_DIR:$PATH

COPY ./src/reports/traditional-json-headers /zap/reports/traditional-json-headers
RUN chmod -R 444 /zap/reports/traditional-json-headers

RUN npm install

RUN npm run build

ENTRYPOINT ["node", "dist/index.js"]
