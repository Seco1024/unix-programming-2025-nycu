FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y \
    build-essential gcc g++ make \
    vim gdb strace curl wget git \
    libcapstone-dev python3 python3-pip \
    locales && \
    locale-gen en_US.UTF-8 && \
    apt clean

ENV LANG=en_US.UTF-8
WORKDIR /work
ENTRYPOINT [ "/bin/bash" ]
