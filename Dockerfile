FROM owasp/zap2docker-weekly

USER root

COPY ./main.py ./requirements.txt ./
COPY ./helpers helpers/

RUN pip3 install -r requirements.txt && mkdir /zap/wrk

ENTRYPOINT ["python3", "main.py"]