# NetPlier (NDSS 2021) with the dependency versions pinned in its repository.
FROM python:3.7-buster

# Debian buster is archived: point apt at archive.debian.org.
RUN sed -i 's|deb.debian.org|archive.debian.org|g; /security/d; /buster-updates/d' /etc/apt/sources.list \
    && apt-get -o Acquire::Check-Valid-Until=false update && apt-get install -y --no-install-recommends mafft libpcap-dev build-essential git \
    && rm -rf /var/lib/apt/lists/*

# minepy, pcapy and Netzob 1.0.2 build from source: preinstall numpy and an old
# Cython and disable build isolation. pandas 0.22.0 no longer builds with current
# packaging tools, so we use 0.25.3, the last release with Python 3.7 wheels.
RUN git clone -q https://github.com/netplier-tool/NetPlier.git /netplier \
    && pip3 install --no-cache-dir numpy==1.19.5 'cython<3' 'wheel<0.38' 'setuptools<60' \
    && cd /netplier && sed -i 's/^pandas==0.22.0/pandas==0.25.3/' requirements.txt \
    && pip3 install --no-cache-dir --no-build-isolation -r requirements.txt

WORKDIR /netplier/netplier
# NetPlier calls mafft-ginsi/linsi/einsi, which Debian installs under /usr/lib/mafft/bin
ENV PATH=/usr/lib/mafft/bin:$PATH
ENV PYTHONPATH=/netplier/netplier
