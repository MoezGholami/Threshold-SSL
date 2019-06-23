FROM ubuntu:18.04
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install --no-install-recommends -y \
        gcc g++ make autoconf automake apt-utils python3 curl wget zip unzip man ca-certificates

RUN cd && wget https://github.com/openssl/openssl/archive/OpenSSL_1_0_2r.zip && unzip OpenSSL_1_0_2r.zip && \
    mv openssl-OpenSSL_1_0_2r openssl && rm OpenSSL_1_0_2r.zip
RUN cd ~/openssl && ./config && make && make install && ln -sf /usr/local/ssl/bin/openssl `which openssl` && rm -rf ~/openssl
