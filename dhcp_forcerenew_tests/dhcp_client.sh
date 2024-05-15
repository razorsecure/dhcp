#!/bin/bash

apt update

apt install --yes iproute2 tcpdump

if [ -f /dhcp/client/dhclient.orig ]; then
  cp /dhcp/client/dhclient.orig /usr/bin
fi
cp /dhcp/client/dhclient /usr/bin

echo "run either"
echo "> dhclient.orig -4 -d -cf /dhcp/dhclient.conf"
echo "> dhclient -4 -d -cf /dhcp/dhclient.conf"
echo "to test"
