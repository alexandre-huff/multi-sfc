#!/bin/bash
# Source: https://sysadmins.co.za/setup-a-site-to-site-ipsec-vpn-with-strongswan-on-ubuntu/

WAN_IFACE=ens5
LAN_IFACE=ens4

ACTION=$1

LOCAL_IP=$2
REMOTE_IP=$3
LOCAL_LAN=$4
REMOTE_LAN=$5

NAT=$6


do_start() {
    # to install IPSec and etc...
    sudo DEBIAN_FRONTEND=noninteractive apt-get install strongswan -y

    sudo chmod 666 /etc/ipsec.secrets
    sudo cat <<EOF > /etc/ipsec.secrets
# source      destination
${LOCAL_IP} ${REMOTE_IP} : PSK "C0qg2oNJmm8RXzXXUnro8o8k0JKlscLpH7oySTvAusN+vbrNtUHZyJNRM81NDTmXrrDOUwSga2KNW7Nn09gLrQ=="
EOF

    sudo chmod 600 /etc/ipsec.secrets

    sudo chmod 666 /etc/ipsec.conf
    sudo cat > /etc/ipsec.conf <<EOF
# basic configuration
config setup
    charondebug="all"
    uniqueids=yes
    strictcrlpolicy=no

# connection to remote datacenter
conn tun0
    authby=secret
    left=%defaultroute
    leftid=${LOCAL_IP}
    leftsubnet=${LOCAL_LAN}
    right=${REMOTE_IP}
    rightsubnet=${REMOTE_LAN}
    ike=aes256-sha2_256-modp1024!
    esp=aes256-sha2_256!
    keyingtries=%forever
    ikelifetime=1h
    lifetime=8h
    dpddelay=30s
    dpdtimeout=120s
    dpdaction=hold
    auto=route
EOF
    sudo chmod 644 /etc/ipsec.conf

    # masquerade packets comming from remote network, so we don't need to confirure static routes on remote routers
    if [ "$NAT" = "True" ]; then
        sudo iptables -t nat -A POSTROUTING -s ${REMOTE_LAN} -d ${LOCAL_LAN} -j MASQUERADE
    fi

    sudo systemctl restart strongswan.service

    # TIP: ping on each side of IPSec in order to start the tunnel working properly
    # I don't now why yet, but by pinging on each side all stuff start working correctly
    # ping -i 10 ${REMOTE_IP} & # this does not work because it stuck the http request until timeout

}

do_stop() {
    sudo systemctl stop strongswan.service

    if [ "$NAT" = "True" ]; then
        sudo iptables -t nat -D POSTROUTING -s ${REMOTE_LAN} -d ${LOCAL_LAN} -j MASQUERADE
    fi

    pkill ping
}

do_status() {
    sudo systemctl status strongswan.service
}


networks() {
        WAN=$(ip -4 -br addr show ${WAN_IFACE} | awk {'print $3'} | sed 's/\/..//')
        LAN=$(ip -4 -br addr show ${LAN_IFACE} | awk {'print $3'} | sed 's/\/..//')
        LAN_NET=$(ip route | grep ${LAN_IFACE} | awk {'print $1'})
        echo -en "wan_ip=${WAN}\nlan_ip=${LAN}\nlan_net=${LAN_NET}"
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