ARG BASE_IMAGE
ARG VERSION
FROM ${BASE_IMAGE}:${VERSION}

# Use explicitly the python version to install the reqirements, and do not update the python3 version
# since slips is relying on version 3.8 and breaks otherwise

RUN apt update -y && apt upgrade -y
RUN apt-get install software-properties-common  -y
RUN add-apt-repository ppa:deadsnakes/ppa -y
# increment this every year to be on the most recent version
RUN apt install python3.12 -y
RUN curl -sS https://bootstrap.pypa.io/get-pip.py | python3.12

RUN mkdir /opt/code
WORKDIR /opt/code

COPY ./requirements.txt /opt/code/requirements.txt
COPY ./apt-requirements.txt /tmp/apt-requirements.txt
COPY ./src/ /opt/code/src

# path to locate the IDSBase implementation
ENV IDS_MODULE=src.models.slips
ENV IDS_CLASS=Slips

RUN python3.12 -m pip install -r requirements.txt
RUN xargs apt install -y < /tmp/apt-requirements.txt

CMD [ "/bin/bash","-c","fastapi dev /opt/code/src/main.py --host 0.0.0.0 --port ${PORT}" ]
