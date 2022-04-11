```
# OTT_via_syslog
Basic proof of concept for turning DNS server logs into OTT data

Traditionally, in order to get OTT data, one must run kprobe in one of two ways:
  Directly on the DNS server - this is not always possible due to the DNS server being an appliance, resource constrained, or non-x86 based
  Connected to a SPAN/Monitor port which is replicating traffic to/from the DNS server.   This is also not always possible due to network topology or resource constraints.
  
The script will run a basic syslog reciever for DNS Server syslog data.  (In my example, pi-hole running on a Raspberry Pi 3)
  You'll need to make sure extending logging is on:
    sudo sh -c 'echo "log-queries=extra" > /etc/dnsmasq.d/99-pihole-log-facility.conf'
    sudo /etc/init.d/pihole-FTL restart
    
To enable rsyslog to send/copy the log file elsewhere, create the file /etc/rsyslog.d/90-pihole.conf with the following (Ubuntu 20)
# Forward logs to kprobe:
*.*     action(type="omfwd" target="192.168.2.44" port="5514" protocol="udp")

module(load="imfile" mode="inotify")
# PiHole
input(type="imfile"
  File="/var/log/pihole.log"
  freshStartTail="on"
  reopenOnTruncate="on"
  Tag="pihole"
  Severity="info"
  Facility="local0"
)

and restart rsyslog with "sudo systemctl restart rsyslog"

On your remote (or it could be the same server, I suppose) server, create a dummy interface (dummy0) for kprobe to monitor:

lmgtfy:  https://foofunc.com/how-to-create-a-virtual-network-interface-in-ubuntu-20-04/

run kprobe as you normally would for OTT, using the dummy0 interface in promiscious mode.
Run this script (maybe in screen, since it's not a daemon)
You can check to see if it's working by running a tcpdump on dummy0  "sudo tcpdump -i dummy0 port 53"

and viola! https://portal.kentik.com/v4/shared/data-explorer/fcfd05a8fff32ce2/dns-syslog-kprobified
```
