#!/bin/bash

ip=10.10.1.12
port=8081

for i in {1..10}
do
	out_file="vazao-nosfc-withvpn-client-server-$i.json"
	echo -e "\nRound $i... File: $out_file"

	iperf3 -c $ip -p $port -t 60 -f m -J > $out_file
	#iperf3 -c $ip -p $port -t 10
	sleep 2
done
