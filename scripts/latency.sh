#!/bin/bash

ip=10.10.1.12

for i in {1..10}
do
	out_file="ping-sfc-client-server-$i.log"
	echo -e "\nRound $i... File: $out_file"

	ping $ip -n -c 60 > $out_file
	#ping $ip -n -c 15
	sleep 2
done
