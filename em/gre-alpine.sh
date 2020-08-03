#!/bin/ash
# use -vx after /bin/bash in order to verbose and debug the whole script

WAN_IFACE=eth2
LAN_IFACE=eth1

ACTION=$1

LOCAL_IP=$2
REMOTE_IP=$3
GRE_LOCAL_IP=$4
GRE_REMOTE_IP=$5
ROUTE_NET_HOST=$6
NAT=$7

do_start() {
        #set -x # activate debugging from here
        ip tunnel add tun0 mode gre remote ${REMOTE_IP} local ${LOCAL_IP} ttl 64
        ip addr add ${GRE_LOCAL_IP} dev tun0
        ip link set tun0 up
        ip route add ${ROUTE_NET_HOST} via ${GRE_REMOTE_IP}

        if [ "$NAT" = "True" ]; then
            iptables -t nat -A POSTROUTING -o ${LAN_IFACE} -j MASQUERADE
        fi
        #set +x # stop debugging from here
}

do_stop() {
        ip link set tun0 down
        ip link del tun0

        iptables -t nat -D POSTROUTING -o ${LAN_IFACE} -j MASQUERADE
}

do_status() {
        echo "=============== LINK  ==============="
        ip link show tun0
        echo "=============== ADDR  ==============="
        ip addr show tun0 |grep inet
        echo "=============== ROUTE ==============="
        ip route show |grep tun0
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
