FROM python:3.8-slim

ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV PIP_NO_CACHE_DIR=off

# Install applications
RUN apt-get update -y

# Install nfslib
RUN apt install -y wget cmake
RUN wget https://github.com/sahlberg/libnfs/archive/refs/tags/libnfs-4.0.0.tar.gz -O /tmp/libnfs.tar.gz
WORKDIR /tmp
RUN tar --extract -f /tmp/libnfs.tar.gz -C /tmp/
WORKDIR /tmp/libnfs-libnfs-4.0.0
RUN cmake . && \
    make && \
    make install
RUN rm -rf /tmp/libnfs.tar.gz /tmp/libnfs-libnfs-4.0.0
RUN apt remove -y wget cmake && \
    apt-get -y autoremove && \
    apt-get clean

# Install Smart File Hunter and its requirements
RUN apt-get install -y python3-magic gcc zip unzip unrar-free p7zip-full
WORKDIR /opt/smartfilehunter
COPY ./sfh .
COPY requirements.txt .
RUN pip install -r requirements.txt
RUN rm -f requirements.txt

# Do cleanups
RUN apt-get -y autoremove && \
    apt-get clean

# ENTRYPOINT ["bash"]
ENTRYPOINT ["./filehunter.py"]
