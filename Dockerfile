FROM owasp/zap2docker-weekly

USER root

COPY ./main.py ./requirements.txt ./
COPY ./helpers helpers/
COPY ./hooks hooks/
COPY ./model model/
COPY ./scripts /home/zap/.ZAP_D/scripts/scripts/active/
RUN chmod 777 /home/zap/.ZAP_D/scripts/scripts/active/

RUN pip3 install -r requirements.txt && mkdir /zap/wrk && cd /opt \
	&& wget -qO- -O geckodriver.tar.gz https://github.com/mozilla/geckodriver/releases/download/v0.29.0/geckodriver-v0.29.0-linux64.tar.gz \
	&& tar -xvzf geckodriver.tar.gz \
	&& chmod +x geckodriver \
	&& ln -s /opt/geckodriver /usr/bin/geckodriver \
	&& export PATH=$PATH:/usr/bin/geckodriver

ENTRYPOINT ["python3", "main.py"]