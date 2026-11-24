FROM debian:bookworm-slim AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        autoconf automake build-essential ca-certificates git libssl-dev libtool pkg-config \
    && rm -rf /var/lib/apt/lists/*

# 固定官方 v0.10.0 对应提交，避免标签移动后构建到其他源码。
RUN git clone --depth 1 --branch v0.10.0 https://github.com/certnanny/sscep.git /src/sscep \
    && test "$(git -C /src/sscep rev-parse HEAD)" = "b3f9798d56d0f6474b491204ff426d80fd4010a7"

WORKDIR /src/sscep
RUN autoreconf -fi \
    && ./configure \
    && make -j"$(nproc)" \
    && make install

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 openssl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/sscep /usr/local/bin/sscep

WORKDIR /work
CMD ["sleep", "infinity"]
