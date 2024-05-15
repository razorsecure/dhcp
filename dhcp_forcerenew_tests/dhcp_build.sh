#!/bin/bash

apt update
apt install --yes build-essential
cd /dhcp
make
