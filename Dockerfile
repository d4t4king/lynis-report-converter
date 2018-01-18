FROM debian:stretch-slim

ENV DEBIAN_FRONTEND noninteractive

RUN useradd -d /lynis-report-converter -U lynis

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
       htmldoc libxml-writer-perl libarchive-zip-perl libjson-perl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY . /lynis-report-converter

USER lynis

WORKDIR /lynis-report-converter

ENTRYPOINT ["/lynis-report-converter/lynis-report-converter.pl"]
CMD ["--help"]
