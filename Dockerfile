FROM python:3.9-slim as base

ENV LD_LIBRARY_PATH=/usr/local/lib \
    PYTHONFAULTHANDLER=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=random \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100 \
    PATH="/opt/smartfilehunter/.venv/bin:${PATH}" \
    VIRTUAL_ENV="/opt/smartfilehunter/.venv/"

WORKDIR /opt/smartfilehunter

RUN apt update -y && \
    apt install -y ca-certificates openssl apt-transport-https python3-magic zip unzip unrar-free p7zip-full vim git

# Setup container
FROM base as builder
ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# Setup and install nfslib
WORKDIR /tmp/libnfs-libnfs-4.0.0
RUN apt-get install -y wget cmake && \
    wget https://github.com/sahlberg/libnfs/archive/refs/tags/libnfs-4.0.0.tar.gz -O /tmp/libnfs.tar.gz && \
    tar --extract -f /tmp/libnfs.tar.gz -C /tmp/ && \
    cmake . && \
    make && \
    make install

# Setup and install Poetry
ENV POETRY_HOME="/opt/poetry" \
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    POETRY_NO_INTERACTION=1 \
    POETRY_VERSION=1.1.13

WORKDIR /opt/smartfilehunter/
COPY pyproject.toml /opt/smartfilehunter/
RUN pip install "poetry==$POETRY_VERSION" && \
    poetry install --no-root --no-dev


# Setup and install Smart File Hunter
FROM base as final
COPY --from=builder /usr/local/lib/libnfs.* /usr/local/lib/
COPY --from=builder /opt/smartfilehunter/.venv /opt/smartfilehunter/.venv
WORKDIR /opt/smartfilehunter
COPY ./sfh ./
RUN ln -sT /opt/smartfilehunter/filehunter.py /usr/bin/filehunter

FROM final as production

# Modify .bashrc to prevent copy&paste issues
COPY .bashrc /root/.bashrc
COPY .vimrc /root/.vimrc

RUN ["bash"]
