#!/bin/bash
# use -vx after /bin/bash in order to verbose and debug the whole script

WAN_IFACE=ens5
LAN_IFACE=ens4
ID=100

ACTION=$1

LOCAL_IP=$2
REMOTE_IP=$3
VXLAN_LOCAL_IP=$4
VXLAN_REMOTE_IP=$5
ROUTE_NET_HOST=$6
NAT=$7

do_start() {
        #set -x # activate debugging from here
        sudo ip link add vxlan0 type vxlan id ${ID} local ${LOCAL_IP} remote ${REMOTE_IP} dev ${WAN_IFACE} dstport 4789
        sudo ip addr add ${VXLAN_LOCAL_IP} dev vxlan0
        sudo ip link set vxlan0 up
        sudo ip route add ${ROUTE_NET_HOST} via ${VXLAN_REMOTE_IP}

        if [ "$NAT" = "True" ]; then
            sudo iptables -t nat -A POSTROUTING -o ${LAN_IFACE} -j MASQUERADE
        fi
        #set +x # stop debugging from here
}

do_stop() {
        sudo ip link set vxlan0 down
        sudo ip link del vxlan0

        if [ "$NAT" = "True" ]; then
            sudo iptables -t nat -D POSTROUTING -o ${LAN_IFACE} -j MASQUERADE
        fi
}

do_status() {
        echo "=============== LINK  ==============="
        ip -d link show vxlan0
        echo "=============== ADDR  ==============="
        ip addr show vxlan0 |grep inet
        echo "=============== ROUTE ==============="
        ip route show |grep vxlan0

        if [ "$NAT" = "True" ]; then
            echo "================ NAT ================"
            sudo iptables -t nat -L -n | grep POSTROUTING -A 10
        fi
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

  *)
        ;;

esac;

exit 0
