#!/bin/sh

apk add dnsmasq tcpdump python3 py3-pip
apk add tcpreplay --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community/

pip install --break-system-packages scapy netifaces2

#nft table ip filter
#nft add chain ip filter INPUT { type filter hook input priority 0 \; policy accept \; }

#ip a a 10.160.128.20/24 dev eth0

#echo "to add the block run:"
#echo '> nft add rule ip filter INPUT udp dport 67 counter drop; nft -a list ruleset'
#echo "note the created handle"
#echo "to remove block run:"
#echo '> nft delete rule ip filter INPUT handle ${that number}'

set -x
dnsmasq --log-queries --log-dhcp --log-facility=/dnsmasq.log --bind-interfaces --port=0 --dhcp-range=interface:eth0,172.17.0.10,172.17.0.100,2m

