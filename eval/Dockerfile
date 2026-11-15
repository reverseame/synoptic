# Synoptic quantitative evaluation environment.
# Toolchain versions follow the paper: Pin 3.25, Python 3.10, angr 9.2.62,
# Capstone 5.0.0, radare2 5.8.4. Binsec is upgraded to 0.11.3 below.
# Targets: the four FTP subjects of ProFuzzBench, and its SMTP (Exim) and RTSP (Live555)
# subjects, built with gcc and without fuzzer instrumentation.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential git wget curl ca-certificates xz-utils unzip patch \
        python3 python3-pip python3-dev gdb graphviz libgraphviz-dev pkg-config \
        opam m4 libgmp-dev bubblewrap z3 \
        autoconf automake libtool libssl-dev libcap-dev libpam0g-dev \
        tcpdump tshark procps net-tools sudo file \
    && rm -rf /var/lib/apt/lists/*

# Intel Pin 3.25
RUN wget -q https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.25-98650-g8f6168173-gcc-linux.tar.gz -O /tmp/pin.tgz \
    && tar xzf /tmp/pin.tgz -C /opt && mv /opt/pin-3.25-98650-g8f6168173-gcc-linux /opt/pin-3.25 && rm /tmp/pin.tgz
ENV PIN_ROOT=/opt/pin-3.25

# radare2 5.8.4 (release package; building the tag pulls an incompatible capstone)
RUN wget -q https://github.com/radareorg/radare2/releases/download/5.8.4/radare2_5.8.4_amd64.deb -O /tmp/r2.deb \
    && apt-get update && apt-get install -y /tmp/r2.deb && rm -rf /tmp/r2.deb /var/lib/apt/lists/*

# Python dependencies (capstone 5.0.0 needs setuptools with pkg_resources)
RUN pip3 install --no-cache-dir 'setuptools<70' wheel \
    && pip3 install --no-cache-dir capstone==5.0.0 r2pipe graphviz PyPDF2 angr==9.2.62 scapy

# Binsec 0.8.0 (OCaml 4.14)
RUN opam init -y --disable-sandboxing --bare \
    && opam switch create 4.14.1 -y \
    && opam install -y --switch=4.14.1 binsec.0.8.0 \
    && opam clean -a -c -s --logs
ENV PATH=/root/.opam/4.14.1/bin:$PATH
# x86-64 decoding in Binsec 0.8.0 comes from the optional unisim_archisec package
RUN opam install -y --switch=4.14.1 unisim_archisec binsec.0.8.0 && opam clean -a -c -s --logs

# Accounts and directories used by the ProFuzzBench configurations and seeds
RUN useradd -m -s /bin/bash ubuntu && echo 'ubuntu:ubuntu' | chpasswd \
    && useradd -m -s /bin/bash fuzzing && echo 'fuzzing:fuzzing' | chpasswd \
    && (getent group ftp || groupadd ftp) && (id ftp || useradd -m -g ftp ftp) \
    && mkdir -p /home/ubuntu/ftpshare /home/ubuntu/experiments \
    && chown -R ubuntu:ubuntu /home/ubuntu

ENV TARGETS=/opt/targets
RUN git clone -q https://github.com/profuzzbench/profuzzbench.git /opt/profuzzbench \
    && ln -s /opt/profuzzbench/subjects/FTP /opt/subjects

# ProFTPD 1.3.8 with default configure options (the configuration of the paper's case study)
RUN git clone -q --depth 1 --branch v1.3.8 https://github.com/proftpd/proftpd.git $TARGETS/proftpd-1.3.8 \
    && cd $TARGETS/proftpd-1.3.8 && ./configure >/dev/null && make -j4 >/dev/null

# ProFTPD (ProFuzzBench commit and configure options)
RUN git clone -q https://github.com/proftpd/proftpd.git $TARGETS/proftpd \
    && cd $TARGETS/proftpd && git checkout -q 4017eff8 \
    && ./configure --enable-devel=nodaemon:nofork >/dev/null && make -j4 >/dev/null

# LightFTP needs GnuTLS headers (separate layer to keep the Binsec layer cached)
RUN apt-get update && apt-get install -y --no-install-recommends libgnutls28-dev && rm -rf /var/lib/apt/lists/*

# LightFTP (fuzzing.patch makes it serve one session on the port given as argv[2])
RUN git clone -q https://github.com/hfiref0x/LightFTP.git $TARGETS/lightftp \
    && cd $TARGETS/lightftp && git checkout -q 5980ea1 \
    && patch -p1 < /opt/subjects/LightFTP/fuzzing.patch \
    && cd Source/Release && make CC=gcc clean all >/dev/null \
    && git clone -q https://github.com/profuzzbench/aflnet.git /tmp/aflnet \
    && cp /tmp/aflnet/tutorials/lightftp/fftp.conf . \
    && cp -r /tmp/aflnet/tutorials/lightftp/certificate /home/ubuntu/ && rm -rf /tmp/aflnet

# Pure-FTPd
RUN git clone -q https://github.com/jedisct1/pure-ftpd.git $TARGETS/pureftpd \
    && cd $TARGETS/pureftpd && git checkout -q c21b45f \
    && patch -p1 < /opt/subjects/PureFTPD/fuzzing.patch \
    && ./autogen.sh >/dev/null 2>&1 && ./configure --without-privsep --without-capabilities >/dev/null && make -j4 >/dev/null

# bftpd 5.7
RUN wget -q https://sourceforge.net/projects/bftpd/files/bftpd/bftpd-5.7/bftpd-5.7.tar.gz -O /tmp/bftpd.tgz \
    && mkdir -p $TARGETS/bftpd && tar xzf /tmp/bftpd.tgz -C $TARGETS/bftpd --strip-components=1 \
    && cd $TARGETS/bftpd && patch -p1 < /opt/subjects/BFTPD/fuzzing.patch && make CC="gcc -fcommon" clean all >/dev/null

# angr 9.2.62 breaks with pycparser >= 2.22 (read-only lexer attributes)
RUN pip3 install --no-cache-dir pycparser==2.21

# Binsec 0.11.3 (latest release) with the native Bitwuzla binding, which Binsec selects by
# default when available. Installed after the targets so that their binaries stay
# byte-identical to those of the runs made with Binsec 0.8.0.
RUN opam update -y \
    && opam install -y --switch=4.14.1 bitwuzla-cxx binsec.0.11.3 unisim_archisec \
    && opam clean -a -c -s --logs

# Targets of two other text protocols of ProFuzzBench, added after the FTP runs (the layers above,
# and therefore the FTP binaries, are unchanged): Exim (SMTP) and Live555 (RTSP), with the
# ProFuzzBench commits and patches.
RUN apt-get update && apt-get install -y --no-install-recommends libpcre3-dev libdb-dev libgdbm-dev psmisc \
    && rm -rf /var/lib/apt/lists/*
ENV PFB=/opt/profuzzbench/subjects

# Exim, installed into /usr/exim and configured with the ProFuzzBench configure patch
RUN git clone -q https://github.com/Exim/exim $TARGETS/exim && cd $TARGETS/exim && git checkout -q 38903fb \
    && patch -p1 < $PFB/SMTP/Exim/exim-rand.patch && patch -p1 < $PFB/SMTP/Exim/exim-log-bug.patch \
    && cd src && mkdir Local && cp src/EDITME Local/Makefile && (cd Local && patch -p1 < $PFB/SMTP/Exim/exim.patch) \
    && make clean all install >/dev/null \
    && cd /usr/exim && patch -p1 < $PFB/SMTP/Exim/exim.configure.patch && chmod 1777 /var/mail

# Live555 (testOnDemandRTSPServer with the AFLNet sample media); fuzzing.patch selects the AFL
# compilers, which we replace by the system ones
RUN git clone -q https://github.com/rgaufman/live555.git $TARGETS/live555 && cd $TARGETS/live555 && git checkout -q ceeb4f4 \
    && patch -p1 < $PFB/RTSP/Live555/fuzzing.patch \
    && sed -i 's/afl-clang-fast++/c++/g; s/afl-clang-fast/cc/g' config.linux \
    && ./genMakefiles linux && make -j4 >/dev/null \
    && git clone -q --depth 1 https://github.com/profuzzbench/aflnet.git /tmp/aflnet \
    && cp /tmp/aflnet/tutorials/live555/sample_media_sources/*.* testProgs/ && rm -rf /tmp/aflnet

# Synoptic (build context = repository root) and its pintool
COPY . /opt/synoptic
RUN cd /opt/synoptic/synoptic/servertracer && make PIN_ROOT=$PIN_ROOT >/dev/null

WORKDIR /opt/synoptic
