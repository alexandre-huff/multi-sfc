#!/bin/bash
# use -vx after /bin/bash in order to verbose and debug the whole script

WAN_IFACE=ens5
LAN_IFACE=ens4

ACTION=$1

LOCAL_IP=$2
REMOTE_IP=$3
GRE_LOCAL_IP=$4
GRE_REMOTE_IP=$5
ROUTE_NET_HOST=$6
NAT=$7

do_start() {
        #set -x # activate debugging from here
        sudo ip tunnel add tun0 mode gre remote ${REMOTE_IP} local ${LOCAL_IP} ttl 64
        sudo ip addr add ${GRE_LOCAL_IP} dev tun0
        sudo ip link set tun0 up
        sudo ip route add ${ROUTE_NET_HOST} via ${GRE_REMOTE_IP}

        if [ "$NAT" = "True" ]; then
            sudo iptables -t nat -A POSTROUTING -o ${LAN_IFACE} -j MASQUERADE
        fi
        #set +x # stop debugging from here
}

do_stop() {
        sudo ip link set tun0 down
        sudo ip link del tun0

        sudo iptables -t nat -D POSTROUTING -o ${LAN_IFACE} -j MASQUERADE
}

do_status() {
        echo "=============== LINK  ==============="
        ip -d link show vxlan0
        echo "=============== ADDR  ==============="
        ip addr show vxlan0 |grep inet
        echo "=============== ROUTE ==============="
        ip route show |grep vxlan0
        echo "================ NAT ================"
        sudo iptables -t nat -L -n | grep POSTROUTING -A 10
}

networks() {
        WAN=$(ip -4 -br addr show ${WAN_IFACE} | awk {'print $3'} | sed 's/\/..//')
        LAN=$(ip -4 -br addr show ${LAN_IFACE} | awk {'print $3'} | sed 's/\/..//')
        LAN_NET=$(ip route | grep ${LAN_IFACE} | awk {'print $1'})
        GATEWAY=$(ip route | grep default | awk {'print $3'})
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
