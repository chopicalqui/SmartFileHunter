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

RUN apt-get update && \
    apt-get install -y python3-magic zip unzip unrar-free p7zip-full


# Setup container
FROM base as builder
ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# Setup and install nfslib
RUN apt-get install -y wget cmake
RUN wget https://github.com/sahlberg/libnfs/archive/refs/tags/libnfs-4.0.0.tar.gz -O /tmp/libnfs.tar.gz
WORKDIR /tmp
RUN tar --extract -f /tmp/libnfs.tar.gz -C /tmp/
WORKDIR /tmp/libnfs-libnfs-4.0.0
RUN cmake . && \
    make && \
    make install

# Setup and install Poetry
ENV POETRY_HOME="/opt/poetry" \
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    POETRY_NO_INTERACTION=1 \
    POETRY_VERSION=1.1.8

RUN pip install "poetry==$POETRY_VERSION"
COPY pyproject.toml poetry.lock /opt/smartfilehunter/
WORKDIR /opt/smartfilehunter/
RUN poetry install --no-root --no-dev
ENTRYPOINT ["bash"]

# Setup and install Smart File Hunter
FROM base as final
# COPY --from=builder /usr/local/include/nfsc /usr/local/include/nfsc/
# COPY --from=builder /usr/local/lib/cmake/libnfs /usr/local/lib/cmake/libnfs/
COPY --from=builder /usr/local/lib/libnfs.* /usr/local/lib/
COPY --from=builder /opt/smartfilehunter/.venv /opt/smartfilehunter/.venv
WORKDIR /opt/smartfilehunter
COPY ./sfh ./

# ENTRYPOINT ["bash"]
ENTRYPOINT ["./filehunter.py"]
