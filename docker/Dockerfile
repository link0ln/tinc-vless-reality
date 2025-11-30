# ==============================================================================
# Stage 1: Build tinc-vless static binary
# ==============================================================================
FROM alpine:3.19 AS builder

RUN apk add --no-cache \
    build-base \
    autoconf \
    automake \
    libtool \
    texinfo \
    linux-headers \
    # OpenSSL for VLESS/Reality TLS
    openssl-dev \
    openssl-libs-static \
    # Compression
    zlib-dev \
    zlib-static \
    lzo-dev \
    # Terminal UI
    ncurses-dev \
    ncurses-static \
    readline-dev \
    readline-static

WORKDIR /build

# Copy tinc source
COPY . /build/tinc-vless

WORKDIR /build/tinc-vless

# Build tinc (dynamic linking for simplicity)
RUN autoreconf -fsi && \
    CFLAGS="-O2" \
    ./configure \
        --prefix=/usr \
        --sysconfdir=/etc \
        --localstatedir=/var \
        --with-openssl && \
    make -j$(nproc) && \
    make install DESTDIR=/install && \
    # Strip binaries (both are in /usr/sbin)
    strip /install/usr/sbin/tincd /install/usr/sbin/tinc && \
    # Show binary info
    ls -lh /install/usr/sbin/ && \
    file /install/usr/sbin/tincd && \
    ldd /install/usr/sbin/tincd

# ==============================================================================
# Stage 2: Minimal runtime image
# ==============================================================================
FROM alpine:3.19

# Install runtime libraries and utilities
RUN apk add --no-cache \
    # Runtime libraries for tinc
    libssl3 \
    libcrypto3 \
    zlib \
    lzo \
    ncurses-libs \
    readline \
    # Network utilities (ifconfig, netstat)
    net-tools \
    # Modern network tools (ip, ss)
    iproute2 \
    # Firewall
    iptables \
    # Testing tools
    iputils \
    iperf3 \
    bind-tools \
    # TLS utilities
    openssl \
    # Shell
    bash

# Copy tinc binaries
COPY --from=builder /install/usr/sbin/tincd /usr/sbin/tincd
COPY --from=builder /install/usr/sbin/tinc /usr/sbin/tinc

# Create required directories
RUN mkdir -p /etc/tinc /var/run/tinc /var/log/tinc

# Copy entrypoint
COPY docker/scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Verify utilities work
RUN echo "=== Verifying utilities ===" && \
    ifconfig --version 2>&1 | head -1 || ifconfig lo && \
    netstat --version 2>&1 | head -1 || netstat -i && \
    /usr/sbin/tincd --version 2>&1 | head -1 && \
    /usr/sbin/tinc --version 2>&1 | head -1 && \
    echo "=== All OK ==="

ENTRYPOINT ["/entrypoint.sh"]
CMD ["tincd", "-D", "-d0"]
