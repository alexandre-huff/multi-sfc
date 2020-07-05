#!/bin/ash
# use -vx after /bin/bash in order to verbose and debug the whole script

WAN_IFACE=eth2
LAN_IFACE=eth1
ID=100

ACTION=$1

LOCAL_IP=$2
REMOTE_IP=$3
VXLAN_LOCAL_IP=$4
VXLAN_REMOTE_IP=$5
ROUTE_NET_HOST=$6
NAT=$7

# Current version of Busybox (1.31.1) in Alpine does not work with VXLAN
# We are using GRE tunnels instead of VXLAN

do_start() {
        #set -x # activate debugging from here
        ip link add vxlan0 type vxlan id ${ID} local ${LOCAL_IP} remote ${REMOTE_IP} dev ${WAN_IFACE} dstport 4789
        ip addr add ${VXLAN_LOCAL_IP} dev vxlan0
        ip link set vxlan0 up
        ip route add ${ROUTE_NET_HOST} via ${VXLAN_REMOTE_IP}

        if [ "$NAT" = "True" ]; then
            iptables -t nat -A POSTROUTING -o ${LAN_IFACE} -j MASQUERADE
        fi
        #set +x # stop debugging from here
}

do_stop() {
        ip link set vxlan0 down
        ip link del vxlan0

        iptables -t nat -D POSTROUTING -o ${LAN_IFACE} -j MASQUERADE
}

do_status() {
        echo "=============== LINK  ==============="
        ip link show vxlan0
        echo "=============== ADDR  ==============="
        ip addr show vxlan0 |grep inet
        echo "=============== ROUTE ==============="
        ip route show |grep vxlan0
        echo "================ NAT ================"
        iptables -t nat -L -n | grep POSTROUTING -A 10
}

networks() {
        WAN=$(ip -4 -o addr show ${WAN_IFACE} | awk '{print $4}' | cut -d / -f 1)
        LAN=$(ip -4 -o addr show ${LAN_IFACE} | awk '{print $4}' | cut -d / -f 1)
        LAN_NET=$(ip route | grep ${LAN_IFACE} | awk '!/default/ {print $1}')
        GATEWAY=$(ip route | grep default | awk '{print $3}')
        echo -en "wan_ip=${WAN}\nlan_ip=${LAN}\nlan_net=${LAN_NET}\ndefault_gw=${GATEWAY}"
}

case "${ACTION}" in
  start)
        do_start
        ;;

  stop)
        do_stop
        ;;

  restart)
        do_stop
        sleep 2
        do_start
        ;;

  status)
        do_status
        ;;

  networks)
        networks
        ;;

  *)
        ;;

esac;

exit 0
