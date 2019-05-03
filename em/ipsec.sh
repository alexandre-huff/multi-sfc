#!/bin/bash
# Source: https://sysadmins.co.za/setup-a-site-to-site-ipsec-vpn-with-strongswan-on-ubuntu/

LOCAL_IP=172.24.240.7
REMOTE_IP=172.24.241.10
LOCAL_LAN=10.10.0.0/24
REMOTE_LAN=10.10.1.0/24



# to install IPSec and etc...
sudo apt install strongswan -y

sudo chmod 666 /etc/ipsec.secrets
sudo cat <<EOF > /etc/ipsec.secrets
# source      destination
${LOCAL_IP} ${REMOTE_IP} : PSK "C0qg2oNJmm8RXzXXUnro8o8k0JKlscLpH7oySTvAusN+vbrNtUHZyJNRM81NDTmXrrDOUwSga2KNW7Nn09gLrQ=="
EOF
sudo chmod 600 /etc/ipsec.secrets

sudo chmod 666 /etc/ipsec.conf
sudo cat > /etc/ipsec.conf << EOF
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
	keyingtries=0
	ikelifetime=1h
	lifetime=8h
	dpddelay=30
	dpdtimeout=120
	dpdaction=restart
	auto=start
EOF
sudo chmod 644 /etc/ipsec.conf

# masquerade packets comming from remote network, so we don't need to confirure static routes on remote routers
sudo iptables -t nat -A POSTROUTING -s ${REMOTE_LAN} -d ${LOCAL_LAN} -j MASQUERADE

sudo systemctl restart strongswan.service
# TIP: ping on each side of IPSec in order to start the tunnel working properly
# I don't now why yet, but by pinging on each side all stuff start working correctly
