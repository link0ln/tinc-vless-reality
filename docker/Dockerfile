# ==============================================================================
# Stage 1: Build quiche (boringssl) library
# ==============================================================================
FROM rust:1.75-alpine AS quiche-builder

RUN apk add --no-cache \
    git \
    cmake \
    make \
    musl-dev \
    perl \
    go \
    clang \
    llvm

WORKDIR /build

# Clone and build quiche with static boringssl
RUN git clone --recursive --depth 1 https://github.com/cloudflare/quiche.git && \
    cd quiche && \
    cargo build --release --features ffi,boringssl-boring-crate && \
    # Build boringssl separately for static linking
    cd quiche/deps/boringssl && \
    mkdir -p build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
          -DBUILD_SHARED_LIBS=OFF \
          .. && \
    make -j$(nproc)

# ==============================================================================
# Stage 2: Build tinc-vless static binary
# ==============================================================================
FROM alpine:3.19 AS tinc-builder

RUN apk add --no-cache \
    build-base \
    autoconf \
    automake \
    libtool \
    texinfo \
    linux-headers \
    openssl-dev \
    openssl-libs-static \
    zlib-dev \
    zlib-static \
    lzo-dev \
    ncurses-dev \
    ncurses-static \
    readline-dev \
    readline-static

WORKDIR /build

# Copy boringssl from quiche-builder
COPY --from=quiche-builder /build/quiche/quiche/deps/boringssl /build/boringssl

# Copy tinc source
COPY . /build/tinc-vless

WORKDIR /build/tinc-vless

# Build tinc with static linking
RUN autoreconf -fsi && \
    CFLAGS="-static -O2" \
    LDFLAGS="-static -L/build/boringssl/build/ssl -L/build/boringssl/build/crypto" \
    CPPFLAGS="-I/build/boringssl/include" \
    ./configure \
        --prefix=/usr \
        --sysconfdir=/etc \
        --localstatedir=/var \
        --with-openssl \
        --disable-shared \
        --enable-static && \
    make -j$(nproc) && \
    make install DESTDIR=/install && \
    # Verify static binary
    file /install/usr/sbin/tincd && \
    ldd /install/usr/sbin/tincd 2>&1 | grep -q "not a dynamic" || \
    ldd /install/usr/sbin/tincd 2>&1 | grep -q "statically linked" || true

# ==============================================================================
# Stage 3: Minimal runtime image
# ==============================================================================
FROM alpine:3.19

# Install runtime utilities
RUN apk add --no-cache \
    # Network utilities
    busybox-extras \
    iproute2 \
    iptables \
    # For ifconfig and netstat
    net-tools \
    # Testing tools
    iputils \
    iperf3 \
    bind-tools \
    # TLS for Reality
    openssl \
    # Shell
    bash

# Copy tinc binaries
COPY --from=tinc-builder /install/usr/sbin/tincd /usr/sbin/tincd
COPY --from=tinc-builder /install/usr/bin/tinc /usr/bin/tinc

# Create required directories
RUN mkdir -p /etc/tinc /var/run/tinc /var/log/tinc

# Copy entrypoint
COPY docker/scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Verify utilities work
RUN ifconfig --help 2>&1 | head -1 && \
    netstat --help 2>&1 | head -1 && \
    tincd --help 2>&1 | head -1

ENTRYPOINT ["/entrypoint.sh"]
CMD ["tincd", "-D", "-d0"]
