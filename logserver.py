#!/usr/bin/python3

import logging
from datetime import date
from socketserver import BaseRequestHandler, UDPServer
from scapy.all import Ether, DNS, DNSQR, DNSRR, IP, sr1, send, sendp, UDP
import re

serverIP = '10.10.10.10'  # this can be any valid IP address, it doesn't really matter


class SyslogHandler(BaseRequestHandler):
	"""
	Server handler is required to handle udp request.
	See examples: https://www.programcreek.com/python/example/73643/SocketServer.BaseRequestHandler
	"""
	def handle(self):
		data = self.request[0].strip().decode("utf-8")
		#log.info(f"{self.client_address[0]}: {str(data)}")
		print (str(data))
		#query[A] osce14-en-census.trendmicro.com from 192.168.1.66
		#192.168.1.66/65205
		ipPort = re.findall("\d+\.\d+\.\d+\.\d+/\d+", str(data))
		#print(ipPort)
		ip,port = ipPort[0].split('/')
		#print(ip,port)
		if 'query[A]' in data or 'query[AAAA]' in data:
			if 'query[A]' in data:
				lookup = data.split('query[A] ')
			if 'query[AAAA]' in data:	
				lookup = data.split('query[AAAA] ')
			#print (lookup[1])
			query,host = lookup[1].split(' from ')
			print (query,host)
			dns_req = IP(dst=str(serverIP),src=str(ip))/UDP(dport=53,sport=int(port))/DNS(id=777, rd=1, qd=DNSQR(qname=query))
			sendp(Ether(dst='ff:ff:ff:ff:ff:ff')/dns_req, iface="dummy0",verbose=0)
		if 'cached' in data or 'reply' in data:
			if 'cached' in data:
				lookup = data.split('cached ')
			if 'reply' in data:	
				lookup = data.split('reply ')
			query,host = lookup[1].split(' is ')
			print (ip,query,host,int(port))			
			if len(re.findall("\d+\.\d+\.\d+\.\d+", str(host))) > 0:   #Only dealing with IPv4 addresses for now
				dns_res = IP(dst=str(ip),src=str(serverIP))/UDP(dport=int(port),sport=53)/DNS(id=777, ancount=1,  qd=DNSQR(qname=str(query)), aa=1, qr=1, an=DNSRR(rrname=str(query), rdata=str(host)))
				sendp(Ether(dst='ff:ff:ff:ff:ff:ff')/dns_res, iface="dummy0", verbose=0)

if __name__ == "__main__":
	try:
		syslog = UDPServer(("0.0.0.0", 5514), SyslogHandler)
		print("EZ syslog starts, CTRL-C to stop...")
		syslog.serve_forever(poll_interval=1)
	except KeyboardInterrupt:
		exit("Ctrl-C detected, exit.")
