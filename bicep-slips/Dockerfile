ARG BASE_IMAGE
ARG VERSION
FROM ${BASE_IMAGE}:${VERSION}


RUN apt update -y && apt upgrade -y
RUN apt-get install software-properties-common -y
RUN add-apt-repository ppa:deadsnakes/ppa -y
RUN apt install python3.12 python3-pip -y
RUN echo "alias python3=python3.12" >> ~/.bashrc


RUN mkdir /opt/code
WORKDIR /opt/code

COPY ./requirements.txt /opt/code/requirements.txt
COPY ./src/ /opt/code/src

# path to locate the IDSBase implementation
ENV IDS_MODULE=src.models.slips
ENV IDS_CLASS=Slips

RUN pip3 install -r requirements.txt

CMD [ "/bin/bash","-c","fastapi dev /opt/code/src/main.py --host 0.0.0.0 --port ${PORT}" ]