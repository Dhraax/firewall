#!/bin/bash
#
# (sort of) Stateful firewall
# Created: 20080609 by Dhraax
# Last Modification: 20200421
#
# Based on Daniel Robbins, at drobbins[at]gentoo.org, guide
# http://www.gentoo.org/doc/en/articles/linux-24-stateful-fw-design.xml
#
# Assumptions:
# - eth0 is your interface facing internet
# Some basic definititions


iptables=`which iptables`
TrustedSources=""
TrustedSourcesBackup=""
TrustedSourcesFTP=""
TrustedSourcesNagios=""
DroppedSources=""
EveryOne="0/0"
Wan=""

# Flush existing rules
echo "Flushing Rules."
$iptables -F
$iptables -F -t nat
$iptables -F -t mangle
$iptables --table nat --delete-chain

# Set default policies
echo "Set default policies."
$iptables -P INPUT DROP
$iptables -P OUTPUT DROP
$iptables -P FORWARD DROP

# Enable traffic based on the connection state
# Input chain state traffic rule
echo "Accept only ESTABLISHED or RELATED state incoming connections."
$iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Output chain state traffic rule
echo "Accept NEW, ESTABLISHED or RELATED state outgoing connections."
$iptables -A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

# Drop incoming traffic from $DroppedSources
echo "Drop INCOMING traffic from ${DroppedSources}."
        for i in ${DroppedSources}
        do
                $iptables -A INPUT -p tcp -s ${i} -j DROP
                $iptables -A INPUT -p udp -s ${i} -j DROP
        done

# Define services running on localhost

# Allow SSH protocol from $TrustedSources and $TrustedSourcesBackup
        for i in ${TrustedSources}
        do
                echo "Allow SSH protocol from ${TrustedSources}."
                $iptables -A INPUT -p tcp --dport 22 -s ${i} -m state --state NEW -j ACCEPT
        done
        for i in ${TrustedSourcesBackup}
        do
                echo "Allow SSH protocol from ${TrustedSourcesBackup}."
                $iptables -A INPUT -p tcp --dport 22 -s ${i} -m state --state NEW -j ACCEPT
        done

# Allow FTP protocol from $EveryOne
        for i in ${EveryOne}
        do
                echo "Allow FTP protocol from ${EveryOne}."
                $iptables -A INPUT -p tcp --dport 21 -s ${i} -m state --state NEW -j ACCEPT
                echo "Allow FTP-DATA from ${EveryOne}."
                $iptables -A INPUT -p tcp --dport 6000:7000 -s ${i} -m state --state NEW -j ACCEPT
        done

# Allow MYSQL protocol from $EveryOne
        for i in ${TrustedSources}
        do
                echo "Allow MySQL protocol from ${TrustedSources}."
                $iptables -A INPUT -p tcp --dport 3306 -s ${i} -m state --state NEW -j ACCEPT
        done

# Allow HTTP protocol from $EveryOne
        for i in ${EveryOne}
        do
                echo "Allow HTTP protocol from ${EveryOne}."
                $iptables -A INPUT -p tcp --dport 80 -s ${i} -m state --state NEW -j ACCEPT
        done
		
# Allow HTTPS protocol from $EveryOne
        for i in ${EveryOne}
        do
                echo "Allow HTTPS protocol from ${EveryOne}."
                $iptables -A INPUT -p tcp --dport 443 -s ${i} -m state --state NEW -j ACCEPT
        done
        
# Allow NRPE port from $TrustedSourcesNagios.
        for i in ${TrustedSourcesNagios}
        do
                echo "Allow NRPE port from ${TrustedSourcesNagios}."
                $iptables -A INPUT -p tcp --dport 5666 -s ${i} -m state --state NEW -j ACCEPT
        done
        
# Allow PSVFTP protocol from $EveryOne
        for i in ${EveryOne}
        do
                echo "Allow PSVFTP protocol from ${EveryOne}."
                $iptables -I INPUT  -p tcp --dport 30000:50000 -s ${i} -m state --state NEW -j ACCEPT
                $iptables -I INPUT  -p udp --dport 30000:50000 -s ${i} -m state --state NEW -j ACCEPT
        done
        
# Allow access to DNS service from everywhere.
echo "Allow access to DNS service from everywhere"
$iptables -A INPUT -s 0/0 -p tcp --dport 53 -m state --state NEW -j ACCEPT
$iptables -A INPUT -s 0/0 -p udp --dport 53 -m state --state NEW -j ACCEPT

# How to handle rejected traffic
$iptables -A INPUT -p tcp -i eth0 -j REJECT --reject-with tcp-reset
$iptables -A INPUT -p udp -i eth0 -j REJECT --reject-with icmp-port-unreachable

# Enforce some common protections
#  Force SYN packets check
echo "Force SYN packets check."
$iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP

#  Force Fragments packets check
echo "Force Fragments packets check."
$iptables -A INPUT -f -j DROP

# Drop Incoming malformed XMAS packets
echo "Drop Incoming malformed XMAS packets."
$iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

# Drop incoming malformed NULL packets
echo "Drop incoming malformed NULL packets."
$iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

# Block reserved private networks incoming from the wan interface
echo "Block reserved private networks incoming from the wan interface."
$iptables -I INPUT -i eth0 -s 10.0.0.0/8 -j DROP
$iptables -I INPUT -i eth0 -s 172.16.0.0/12 -j DROP
$iptables -I INPUT -i eth0 -s 192.168.0.0/16 -j DROP
$iptables -I INPUT -i eth0 -s 127.0.0.0/8 -j DROP

# Define what ICMP protocol messages we allow
# Allow ICMP Ping
echo "Allow ICMP echo-request from ak-alicia"
$iptables -A INPUT -p icmp --icmp-type echo-request -s 190.224.160.17 -j ACCEPT
echo "Allow ICMP echo-request from ak-nagios"
$iptables -A INPUT -p icmp --icmp-type echo-request -s 200.68.116.5 -j ACCEPT


# Block icmp echo-request to all
echo "Block icmp echo-request on wan interface"
$iptables -A INPUT -i eth0 -p icmp --icmp-type echo-request -j DROP

# Allow traffic from/to loopback interface
echo "Allow loopback interface traffic"
$iptables -A INPUT -i lo -j ACCEPT
$iptables -A OUTPUT -o lo -j ACCEPT

# Log invalid packets to syslog
$iptables -A INPUT -m state --state INVALID -m limit --limit 5/minute -j LOG --log-level 5 --log-prefix "INVALID STATE:"
