# Network-trace baselines for the format-inference comparison: NEMESYS and
# Netzob (Format.clusterByAlignment), both through the NEMESYS code base,
# which pins Netzob 2.0.0.
FROM python:3.9-bookworm

RUN echo 'wireshark-common wireshark-common/install-setuid boolean true' | debconf-set-selections - \
    && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y git libpcap-dev tshark \
    && rm -rf /var/lib/apt/lists/*

RUN git clone -q https://github.com/vs-uulm/nemesys.git /nemere \
    && cd /nemere && git checkout -q e98da1d \
    && pip3 install --no-cache-dir -r requirements.txt \
    && pip3 install --no-cache-dir pylstar==0.1.2

WORKDIR /nemere/src
ENV PYTHONPATH=/nemere/src
