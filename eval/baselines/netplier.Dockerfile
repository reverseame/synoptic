# NetPlier (NDSS 2021) with the dependency versions pinned in its repository.
FROM python:3.7-buster

# Debian buster is archived: point apt at archive.debian.org.
RUN sed -i 's|deb.debian.org|archive.debian.org|g; /security/d; /buster-updates/d' /etc/apt/sources.list \
    && apt-get -o Acquire::Check-Valid-Until=false update && apt-get install -y --no-install-recommends mafft libpcap-dev build-essential git \
    && rm -rf /var/lib/apt/lists/*

# minepy and Netzob 1.0.2 need numpy and Cython at build time
RUN git clone -q https://github.com/netplier-tool/NetPlier.git /netplier \
    && pip3 install --no-cache-dir numpy==1.19.5 cython \
    && cd /netplier && pip3 install --no-cache-dir -r requirements.txt

WORKDIR /netplier/netplier
ENV PYTHONPATH=/netplier/netplier
