#!/bin/bash

./throughput.sh 10.10.1.101 8080 vazao-sfc-vxlan-client-server
sleep 5
./latency.sh 10.10.1.101 ping-nosfc-vxlan-client-server
