FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    file \
    make \
    mono-devel \
    binutils-mingw-w64-x86-64 \
    gcc-mingw-w64-x86-64 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src/powerpick-bof

CMD ["make", "all"]
