#!/bin/bash

if [ "$#" -lt "2" ]; then
        echo "Usage: $0 IP NAME*"
        echo -e "\t*used to define the directory and file names."
        exit 1
fi

ip=$1
name=$2
#ip=10.10.1.12

echo -e "========== Running $name ==========\n"

dir="data/$name"
mkdir -p $dir

for i in {1..2}
do
        out_file="$dir/$i.log"
        echo -e "Round $i... File: $out_file"

        #ping $ip -n -c 60 > $out_file
        ping $ip -n -c 5 > $out_file
        sleep 2
done

echo -e ">>>>> Setting read-only permissions <<<<<"
chmod 555 $dir
chmod 444 $dir/*

echo -e "\n============ Done $name ===========\n\n"
