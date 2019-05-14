#!/bin/bash
# use -vx after /bin/bash in order to verbose and debug the whole script

ACTION=$1
LOCAL_IP=$2
REMOTE_IP=$3
IFACE=$4
ID=$5
VXLAN_LOCAL_IP=$6
VXLAN_REMOTE_IP=$7
ROUTE_NET_HOST=$8
ARP_PROXY_REMOTE_HOST=$9
ARP_PROXY_IFACE=$10

do_start() {
        #set -x # activate debugging from here
        sudo ip link add vxlan0 type vxlan id ${ID} local ${LOCAL_IP} remote ${REMOTE_IP} dev ${IFACE} dstport 4789
        sudo ip addr add ${VXLAN_LOCAL_IP} dev vxlan0
        sudo ip link set vxlan0 up
        sudo ip route add ${ROUTE_NET_HOST} via ${VXLAN_REMOTE_IP}
        sudo ip neighbor add proxy ${ARP_PROXY_REMOTE_HOST} dev ${ARP_PROXY_IFACE}
        #set +x # stop debugging from here
}

do_stop() {
        sudo ip link set vxlan0 down
        sudo ip link del vxlan0
        sudo ip neighbor del proxy ${ARP_PROXY_REMOTE_HOST} dev ${ARP_PROXY_IFACE}
}

do_status() {
        echo "=============== LINK  ==============="
        ip -d link show vxlan0
        echo "=============== ADDR  ==============="
        ip addr show vxlan0 |grep inet
        echo "=============== ROUTE ==============="
        ip route show |grep vxlan0
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
        usage

esac;

exit 0
