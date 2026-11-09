# 2026-11-09 10:00:00 by RouterOS 7.16
# software id = DEMO-0000
#
/interface bridge
add name=bridge
/ip address
add address=192.168.88.1/24 interface=bridge network=192.168.88.0
/ip dns
set allow-remote-requests=yes servers=1.1.1.1
/ip firewall nat
add action=masquerade chain=srcnat out-interface=ether1
/ip socks
set enabled=yes
/ip upnp
set enabled=yes
/system identity
set name=cafe-hotspot
