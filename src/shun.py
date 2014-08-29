#!/usr/bin/env python
#########################################################################################################
#
# Automatic Shunning Script for ArcSight
#
# Takes in two parameters, attacker IP address and shun or unshun
#
# Note: python-pexpect will need to be installed on the machine
#
# Originally Written by: TrustedSec - David Kennedy
#
# Intructions: There is a  module that will need to be installed for
# this to operate properly.           
# 
# Download and install pexpect: http://www.noah.org/wiki/pexpect#Download_and_Installation
# 
#
#########################################################################################################
#
# Version 0.1 - Initial release for shunning in ArcSight
# Version 0.2 - Added capability for Advanced Encryption Standard (AES)
# Version 0.2.1 - Ripped out AES
#
##########################################################################################################

import subprocess
import pexpect
import sys
import os
import base64

# Version tracking
VERSION = "0.2"

# Specify username and password for firewalls
USERNAME = "test"
# PASSWORD FOR THE CISCO DEVICE - NOTE MUST BE ENCRYPTED VIA AES
USER_PASSWORD = "test"
# LEAVE BLANK IF IT IS THE SAME - NOTE MUST BE ENCRYPTED VIA AES
ENABLE_PASSWORD = ""

# firewall definitions here
firewalls = ['10.1.1.1']     # FW1

# our function for pexpect and logging into a server to shun
def shun(firewall, attacker, action, USERNAME, USER_PASSWORD, ENABLE_PASSWORD):
	# spawn a child thread to execute our SSH command
	child = pexpect.spawn("ssh %s@%s"%(USERNAME, firewall))
	# wait for the password
	child.expect("assword:", timeout=5)
	# send the password
	child.sendline(USER_PASSWORD)
	# wait for a prompt and switch to enable mode
	child.expect(">", timeout=5)
	# send enable
	child.sendline("en")
	# send enable password
	if ENABLE_PASSWORD == "":
		child.sendline(PASSWORD)
	# if we are using a different enable password
	if ENABLE_PASSWORD != "":
		child.sendline(ENABLE_PASSWORD)
	# if we are looking to shun the attacker IP address
	if action == "1":
		command = "shun " + attacker
	# if we are looking to unshun
	if action == "2":
		command = "no shun " + attacker
	# shun or unshun the attacker
	child.sendline(command)
	# wait for the expected response
	child.expect("#", timeout=5)
	# exit out of the system
	child.sendline("exit")
	# remove child thread
	del(child)

# see if we have valid command line arguments
try:
	# grab the IP address from the command line of the attacker
	attacker = sys.argv[1]
	# grab shun or unshun - this will tell us if we need to unblock the attacker or block
	# 1 equals a shun, 2 equals unshun
	action = sys.argv[2]

	
# if we were not passed the appropriate command line arguments then trigger an alert
except IndexError:
	# print that the proper commands were not given
	print "\n####################################################################"
	print "#"
	print "# Automatic Shunning Script"
	print "#"
	print "# Takes in two parameters, attacker IP address and shun or unshun"
	print "#"
	print "# Note: python-pexpect will need to be installed on the machine"
	print "#"
	print "# Written by: TrustedSec - David Kennedy"
	print "# Basterized By Justin Herman"
	print "#"
	print "####################################################################"
	print "\n[!] The correct command arguments were not given to the shun tool."
	print "[!] Options: Two parameters must be passed, IP Address, shun/1 or unshun/2," 
        print "\n"
	print "\nUsage: python shun.py <ip-address> <1 or 2> "
	sys.exit()


# wrap everything in a try/except block for error catching
try:
	for firewall in firewalls:
		attacker = sys.argv[1]
		action = sys.argv[2]
	# start the shunning process
		shun(firewall, attacker, action, USERNAME, USER_PASSWORD, ENABLE_PASSWORD)
	# if we are shunning
	if action == "1":
		print "Successfully shunned IP Address: %s on FW %s" %(attacker,firewall)
	# if we are unshunning
	if action == '2':
		print "Successfully unshunned IP Address: %s on FW %s" % (attacker,firewall)

# catch all errors and write it out to an error log
except:
	print "Error has occured"
	sys.exit()
