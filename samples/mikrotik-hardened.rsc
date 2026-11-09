# 2026-11-09 10:00:00 by RouterOS 7.16
# hardened example (terse export)
/interface list add name=WAN
/interface list add name=LAN
/ip firewall filter add action=accept chain=input connection-state=established,related,untracked
/ip firewall filter add action=drop chain=input connection-state=invalid
/ip firewall filter add action=accept chain=input protocol=icmp
/ip firewall filter add action=drop chain=input in-interface-list=!LAN comment="drop all not from LAN"
/ip dns set allow-remote-requests=yes servers=1.1.1.1
/ip service set telnet disabled=yes
/ip service set ftp disabled=yes
/ip service set www disabled=yes
/ip service set api disabled=yes
/ip service set api-ssl disabled=yes
/ip service set winbox address=192.168.88.0/24
/ip service set ssh address=192.168.88.0/24
/ip ssh set strong-crypto=yes
/ip neighbor discovery-settings set discover-interface-list=LAN
/tool mac-server set allowed-interface-list=LAN
/tool mac-server mac-winbox set allowed-interface-list=LAN
/tool bandwidth-server set enabled=no
/system ntp client set enabled=yes
/system ntp client servers add address=pool.ntp.org
/system logging action add name=syslog remote=192.168.88.20 target=remote
/system logging add action=syslog topics=info
