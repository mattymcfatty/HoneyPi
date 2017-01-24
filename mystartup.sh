#!/bin/sh
# this forwards iptables for psad
# drop this file in /etc/init.d
# not 100% sure if this is necessary if iptables-persistent is installed

iptables -A INPUT -j LOG
iptables -A FORWARD -j LO
