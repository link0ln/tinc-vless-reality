FROM ubuntu:22.04

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    autoconf \
    automake \
    libtool \
    libssl-dev \
    zlib1g-dev \
    liblzo2-dev \
    libncurses5-dev \
    libreadline-dev \
    git \
    pkg-config \
    net-tools \
    iproute2 \
    iputils-ping \
    curl \
    vim \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Create tinc build directory
WORKDIR /build

# Copy tinc source
COPY . /build/

# Build tinc with VLESS support
RUN autoreconf -fsi && \
    ./configure \
        --prefix=/usr \
        --sysconfdir=/etc \
        --localstatedir=/var \
        --with-openssl \
        --enable-maintainer-mode && \
    make && \
    make install

# Create necessary directories
RUN mkdir -p /etc/tinc /var/run /var/log

# Copy entrypoint script
COPY docker/scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["tincd", "-D", "-d5"]
