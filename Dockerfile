FROM ubuntu:18.04
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install --no-install-recommends -y \
        gcc g++ make autoconf automake apt-utils python3 curl wget zip unzip man ca-certificates vim openssl libssl-dev

RUN mkdir /root/lab
WORKDIR /root/lab
