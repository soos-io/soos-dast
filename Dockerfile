# if the image or tag changes, make sure to update the scan structure tool name and version
FROM soosio/zap2docker-soos as base

USER root

COPY ./main.py ./requirements.txt ./VERSION.txt ./
COPY ./helpers helpers/
COPY ./hooks hooks/
COPY ./model model/
COPY ./scripts/httpsender /home/zap/.ZAP/scripts/scripts/httpsender/
RUN chmod 777 /home/zap/.ZAP/scripts/scripts/httpsender/

COPY ./reports/traditional-json /zap/reports/traditional-json
COPY ./reports/traditional-json-headers /zap/reports/traditional-json-headers
RUN chmod -R 444 /zap/reports/traditional-json
RUN chmod -R 444 /zap/reports/traditional-json-headers

RUN pip3 install -r requirements.txt && mkdir /zap/wrk && cd /opt \
	&& wget -qO- -O geckodriver.tar.gz https://github.com/mozilla/geckodriver/releases/download/v0.30.0/geckodriver-v0.30.0-linux64.tar.gz \
	&& tar -xvzf geckodriver.tar.gz \
	&& chmod +x geckodriver \
	&& ln -s /opt/geckodriver /usr/bin/geckodriver \
	&& export PATH=$PATH:/usr/bin/geckodriver

# Set up the Chrome PPA
RUN wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add -
RUN echo "deb http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list

# Set up Chrome version to be used
ARG CHROME_VERSION="117.0.5938.132-1"

# Set up the Chrome PPA
RUN wget --no-verbose -O /tmp/chrome.deb https://dl.google.com/linux/chrome/deb/pool/main/g/google-chrome-stable/google-chrome-stable_${CHROME_VERSION}_amd64.deb \ 
  && apt-get update \
  && apt install -y /tmp/chrome.deb \
  && rm /tmp/chrome.deb

# Set up Chromedriver Environment variables
ENV CHROMEDRIVER_VERSION 100.0.4896.20
ENV CHROMEDRIVER_DIR /chromedriver
RUN mkdir $CHROMEDRIVER_DIR

# Download and install Chromedriver
RUN wget -q --continue -P $CHROMEDRIVER_DIR "https://chromedriver.storage.googleapis.com/$CHROMEDRIVER_VERSION/chromedriver_linux64.zip"
RUN unzip $CHROMEDRIVER_DIR/chromedriver* -d $CHROMEDRIVER_DIR

# Put Chromedriver into the PATH
ENV PATH $CHROMEDRIVER_DIR:$PATH

RUN cd /zap/plugin && \
	rm -rf ascanrules-* && wget https://github.com/zaproxy/zap-extensions/releases/download/ascanrules-v49/ascanrules-release-49.zap && \
    rm -rf ascanrulesBeta-* && wget https://github.com/zaproxy/zap-extensions/releases/download/ascanrulesBeta-v44/ascanrulesBeta-beta-44.zap && \
	rm -rf commonlib-* && wget https://github.com/zaproxy/zap-extensions/releases/download/commonlib-v1.12.0/commonlib-release-1.12.0.zap && \
	rm -rf network-* && wget https://github.com/zaproxy/zap-extensions/releases/download/network-v0.6.0/network-beta-0.6.0.zap && \
	rm -rf oast-* && wget https://github.com/zaproxy/zap-extensions/releases/download/oast-v0.14.0/oast-beta-0.14.0.zap && \
	rm -rf pscanrules-* && wget https://github.com/zaproxy/zap-extensions/releases/download/pscanrules-v44/pscanrules-release-44.zap && \
    rm -rf pscanrulesBeta-* && wget https://github.com/zaproxy/zap-extensions/releases/download/pscanrulesBeta-v31/pscanrulesBeta-beta-31.zap && \
	chown -R zap:zap /zap
	

FROM base as test
COPY ./tests tests/

ENTRYPOINT ["python3", "-m", "unittest", "tests/tests.py"]

FROM base as production

ENTRYPOINT ["python3", "main.py"]
