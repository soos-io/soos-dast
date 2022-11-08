# if the image or tag changes, make sure to update the scan structure tool name and version
FROM owasp/zap2docker-weekly:w2022-11-07 as base

USER root

COPY ./main.py ./requirements.txt ./VERSION.txt ./
COPY ./helpers helpers/
COPY ./hooks hooks/
COPY ./model model/
COPY ./scripts/httpsender /home/zap/.ZAP_D/scripts/scripts/httpsender/
RUN chmod 777 /home/zap/.ZAP_D/scripts/scripts/httpsender/

COPY ./reports/traditional-json /zap/reports/traditional-json
COPY ./reports/traditional-json-headers /zap/reports/traditional-json-headers
RUN chmod -R 444 /zap/reports/traditional-json
RUN chmod -R 444 /zap/reports/traditional-json-headers

# Reference: https://github.com/mozilla/geckodriver/releases
ENV GECKO_DRIVER_VERSION="v0.32.0"

RUN pip3 install -r requirements.txt && mkdir /zap/wrk && cd /opt \
	&& wget -qO- -O geckodriver.tar.gz "https://github.com/mozilla/geckodriver/releases/download/${GECKO_DRIVER_VERSION}/geckodriver-${GECKO_DRIVER_VERSION}-linux64.tar.gz" \
	&& tar -xvzf geckodriver.tar.gz \
	&& chmod +x geckodriver \
	&& ln -s /opt/geckodriver /usr/bin/geckodriver \
	&& export PATH=$PATH:/usr/bin/geckodriver

# Set up the Chrome PPA
RUN wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add -
RUN echo "deb http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list

# Set up Chrome version to be used
# Reference: https://www.ubuntuupdates.org/ppa/google_chrome
ENV CHROME_VERSION="107.0.5304.87-1"

# Set up the Chrome PPA
RUN wget --no-verbose -O /tmp/chrome.deb "https://dl.google.com/linux/chrome/deb/pool/main/g/google-chrome-stable/google-chrome-stable_${CHROME_VERSION}_amd64.deb" \ 
  && apt-get update \
  && apt install -y /tmp/chrome.deb \
  && rm /tmp/chrome.deb

# Set up Chromedriver Environment variables
# Reference: https://chromedriver.chromium.org/downloads
ENV CHROMEDRIVER_VERSION="107.0.5304.62"
ENV CHROMEDRIVER_DIR /chromedriver
RUN mkdir $CHROMEDRIVER_DIR

# Download and install Chromedriver
RUN wget -q --continue -P $CHROMEDRIVER_DIR "https://chromedriver.storage.googleapis.com/${CHROMEDRIVER_VERSION}/chromedriver_linux64.zip"
RUN unzip $CHROMEDRIVER_DIR/chromedriver* -d $CHROMEDRIVER_DIR

# Put Chromedriver into the PATH
ENV PATH $CHROMEDRIVER_DIR:$PATH

FROM base as test
COPY ./tests tests/

ENTRYPOINT ["python3", "-m", "unittest", "tests/tests.py"]

FROM base as production

ENTRYPOINT ["python3", "main.py"]
