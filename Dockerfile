FROM ubuntu:18.04

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    libmemcached-dev git python3-pip libcurl4-openssl-dev libssl-dev

WORKDIR /app

COPY requirements.txt .

# general requirements for Multi-SFC
RUN python3 -m pip install --no-cache-dir -r requirements.txt

# specific requirements for osmclient
RUN python3 -m pip install --no-cache-dir python-magic \
    && python3 -m pip install --no-cache-dir git+https://osm.etsi.org/gerrit/osm/IM --upgrade \
    && python3 -m pip install --no-cache-dir git+https://osm.etsi.org/gerrit/osm/osmclient

# COPY . .

CMD [ "/bin/bash" ]
