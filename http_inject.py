from scapy.all import *


def parse(packet):
	if packet.haslayer(TCP) and packet.getlayer(TCP).dport == 80 and packet.haslayer(Raw):
		if "GET" in str(packet.getlayer(Raw).load):
			ethernet = packet[Ether]
			ipheader = packet[IP]
			tcpheader = packet[TCP]
			tcpheader.flags = 'R'
			tcpheader.load = "blocked"
			tcpheader.seq = len(tcpheader.load) + tcpheader.seq

			del ipheader.chksum
			del ipheader.len
			del tcpheader.chksum

			packet.show2()
			sendp(packet)
			return

sniff(prn=parse, filter="", store=0) #sniffing tcp

