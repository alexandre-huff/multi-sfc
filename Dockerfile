# Multistage building, we can choose whether or not to enable federation
# CONFIG values: base | federation
ARG CONFIG=federation

FROM ubuntu:20.04 AS base

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    libmemcached-dev git python3-pip libcurl4-openssl-dev libssl-dev libkrb5-dev \
    && apt-get clean

WORKDIR /app

COPY requirements.txt .

# general requirements for Multi-SFC
RUN python3 -m pip install --no-cache-dir -r requirements.txt

# specific requirements for osmclient
RUN python3 -m pip install --no-cache-dir python-magic \
    && python3 -m pip install --no-cache-dir git+https://osm.etsi.org/gerrit/osm/IM@v8.0.4 \
    && python3 -m pip install --no-cache-dir git+https://osm.etsi.org/gerrit/osm/osmclient@v8.0.4


# configuring requirements for federation at this stage
FROM base AS federation

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    apache2 libapache2-mod-wsgi-py3 libapache2-mod-shib2 \
    && apt-get clean

WORKDIR /app

# configuring Apache and WSGI
COPY apache/multisfc.* apache/
RUN sed -i "1i ServerName\ $HOSTNAME" /etc/apache2/apache2.conf \
    && sed -i 's/Listen\ 80/\#Listen\ 80/' /etc/apache2/ports.conf \
    && a2dissite 000-default \
    && ln -s $(pwd)/apache/multisfc.conf /etc/apache2/sites-enabled/multisfc.conf

# configuring Shibboleth
COPY shibboleth/*.xml /etc/shibboleth/
RUN shib-keygen -y 10 -o /etc/shibboleth/ -h sp.multisfc.local
# IMPORTANT: Since we run shib-keygen, the SP metadata needs to be updated in the IdP.
# New certificates are generated on each build and they won't match with the older ones
# previously submitted to the IdP.


# choose whether or not to enable federation
FROM ${CONFIG} AS final
# mounting volumes using docker-compose, no need to copy
# COPY . .

ENTRYPOINT [ "/app/docker-entrypoint.sh" ]
CMD [ "multisfc" ]
