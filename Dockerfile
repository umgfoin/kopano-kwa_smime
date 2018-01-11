FROM ubuntu:16.04

RUN apt-get update
RUN apt-get install -y phpmd phpunit libfaketime php-xdebug php-gettext php-curl openssl

# Add Jenkins user
RUN useradd -m -u 109 jenkins

# Cleanup
RUN apt-get clean -y && \
  apt-get autoclean -y && \
  apt-get autoremove -y && \
  rm -rf /usr/share/locale/* && \
  rm -rf /var/cache/debconf/*-old && \
  rm -rf /var/lib/apt/lists/* && \
  rm -rf /usr/share/doc/*

