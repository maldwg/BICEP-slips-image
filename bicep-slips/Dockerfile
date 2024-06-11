ARG BASE_IMAGE
ARG VERSION
FROM ${BASE_IMAGE}:${VERSION}

# Use explicitly the python version to install the reqirements, and do not update the python3 version
# since slips is relying on version 3.8 and breaks otherwise

RUN apt update -y && apt upgrade -y
RUN apt-get install software-properties-common iproute2 -y
RUN add-apt-repository ppa:deadsnakes/ppa -y
RUN apt install python3.12 python3.12-distutils -y
RUN curl -sS https://bootstrap.pypa.io/get-pip.py | python3.12


RUN mkdir /opt/code
WORKDIR /opt/code

COPY ./requirements.txt /opt/code/requirements.txt
COPY ./src/ /opt/code/src

# path to locate the IDSBase implementation
ENV IDS_MODULE=src.models.slips
ENV IDS_CLASS=Slips

RUN python3.12 -m pip install -r requirements.txt

CMD [ "/bin/bash","-c","fastapi dev /opt/code/src/main.py --host 0.0.0.0 --port ${PORT}" ]
