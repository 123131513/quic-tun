#!/bin/bash
ip rule add fwmark 1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100

# ip rule add from 10.0.1.1 table 1
# ip rule add from 10.0.2.1 table 2
# ip rule add from 10.0.3.1 table 3

# ip route add 10.0.1.0/24 dev r1-eth1 scope link table 1
# ip route add default via 10.0.1.2 dev r1-eth1 table 1

# ip route add 10.0.2.0/24 dev r1-eth2 scope link table 2
# ip route add default via 10.0.2.2 dev r1-eth2 table 2

# ip route add 10.0.3.0/24 dev r1-eth3 scope link table 3
# ip route add default via 10.0.3.2 dev r1-eth3 table 3

iptables -t mangle -F

iptables -t mangle -N GOST

# 排除DNS服务器的流量
iptables -t mangle -A GOST -p udp -d 8.8.8.8 -j RETURN
iptables -t mangle -A GOST -p udp -d 8.8.4.4 -j RETURN
iptables -t mangle -A GOST -p udp -d 1.1.1.1 -j RETURN
iptables -t mangle -A GOST -p udp -d 9.9.9.9 -j RETURN
iptables -t mangle -A GOST -p udp -d 114.114.114.114 -j RETURN

iptables -t mangle -A GOST -p udp -d 127.0.0.0/8 -j RETURN
iptables -t mangle -A GOST -p udp -d 255.255.255.255/32 -j RETURN
iptables -t mangle -A GOST -p udp -d 192.168.0.0/16 -j RETURN
iptables -t mangle -A GOST -p udp -d 10.0.0.0/24 -j RETURN
iptables -t mangle -A GOST -p udp -d 10.0.1.1/32 -j RETURN
iptables -t mangle -A GOST -p udp -d 10.0.2.1/32 -j RETURN
iptables -t mangle -A GOST -p udp -d 10.0.3.1/32 -j RETURN
iptables -t mangle -A GOST -p udp -m mark --mark 100 -j RETURN 
iptables -t mangle -A GOST -p udp -m mark --mark 0x1 -j RETURN 
iptables -t mangle -A GOST -p udp -j TPROXY --tproxy-mark 0x1/0x1 --on-ip 127.0.0.1 --on-port 12345 
iptables -t mangle -A PREROUTING -p udp -j GOST

iptables -t mangle -N GOST_LOCAL

# 排除DNS服务器的流量
iptables -t mangle -A GOST -p udp -d 8.8.8.8 -j RETURN
iptables -t mangle -A GOST -p udp -d 8.8.4.4 -j RETURN
iptables -t mangle -A GOST -p udp -d 1.1.1.1 -j RETURN
iptables -t mangle -A GOST -p udp -d 9.9.9.9 -j RETURN
iptables -t mangle -A GOST -p udp -d 114.114.114.114 -j RETURN

iptables -t mangle -A GOST_LOCAL -p udp -d 127.0.0.0/8 -j RETURN
iptables -t mangle -A GOST_LOCAL -p udp -d 255.255.255.255/32 -j RETURN
iptables -t mangle -A GOST_LOCAL -p udp -d 192.168.0.0/16 -j RETURN
iptables -t mangle -A GOST_LOCAL -p udp -d 10.0.0.0/24 -j RETURN
iptables -t mangle -A GOST_LOCAL -p udp -d 10.0.7.1/32 -j RETURN
iptables -t mangle -A GOST_LOCAL -p udp -m mark --mark 100 -j RETURN 
iptables -t mangle -A GOST_LOCAL -p udp -m mark --mark 0x1 -j RETURN 
iptables -t mangle -A GOST_LOCAL -p udp -j MARK --set-mark 1
iptables -t mangle -A OUTPUT -p udp -j GOST_LOCAL

