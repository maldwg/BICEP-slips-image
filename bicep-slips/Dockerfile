ARG BASE_IMAGE
ARG VERSION
FROM ${BASE_IMAGE}:${VERSION}

RUN mkdir /opt/code
WORKDIR /opt/code

COPY ./requirements.txt /opt/code/requirements.txt
COPY ./utils/ /opt/code/utils
COPY ./src/ /opt/code/src

RUN pip3 install -r requirements.txt