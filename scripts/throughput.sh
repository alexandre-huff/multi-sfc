#!/bin/bash

if [ "$#" -lt "3" ]; then
        echo "Usage: $0 IP PORT NAME*"
        echo -e "\t*used to define the directory and file names."
        exit 1
fi

ip=$1
port=$2
name=$3
#ip=10.10.1.101
#port=8080

echo -e "========== Running $name ==========\n"

dir="data/$name"
mkdir -p $dir

for i in {1..2}
do
        out_file="$dir/$i.json"
        echo -e "Round $i... File: $out_file"

        iperf3 -c $ip -p $port -t 60 -P 8 -f m -J > $out_file
        #iperf3 -c $ip -p $port -t 2 -P 8 > $out_file
        sleep 2
done

echo -e ">>>>> Setting read-only permissions <<<<<"
chmod 555 $dir
chmod 444 $dir/*

echo -e "\n============ Done $name ===========\n\n"
