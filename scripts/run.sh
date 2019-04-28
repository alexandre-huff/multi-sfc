#!/bin/bash

./vazao.sh 10.10.1.101 8080 vazao-sfc-vxlan-client-server
sleep 5
./latencia.sh 10.10.1.101 ping-nosfc-vxlan-client-server
