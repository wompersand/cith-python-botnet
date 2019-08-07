from rsa import *
import socket
import select
from chat_client_polished import encrypt, decrypt, pad16, depad16
from Crypto.Cipher import AES
import base64
import sys
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

(1) This chat server will work like a chat room.
Once a client sends us data to post, the server will send (forward)
the data to all active clients except for the sending client. This will be done with either CHEAP RSA enryption or AES depending on what the client has chosen. Each client comes up with their own AES shared secret and gives it to the server to be stored in a keyring bound to the client's identity.

AES shared secret exchange is done using CHEAP RSA. This means the client uses the server's public key to encrypt and send the shared secret to the server.

(2) Data section of TCP packet will be encrypted using either CHEAP RSA or AES.
'''
def broadcast_more_like_breadcast(sender_socket, message):
	# the conditional in this FOR loop is so that we do not send this message
	# to either the master socket or the sending client.
	for sock in ACTIVE_CONNECTIONS_LIST:

		if sock != sender_socket and sock != master_socket:
			try:
				message_1 = message
				fd = sock.fileno()
				# AES
				if NO_ENCRYPTION:
					sock.send(message_1)
					
				elif fd in ACTIVE_CONNECTIONS_KEYRING_AES:
					print "\n[*] broadcasting using AES on connection {}".format(fd)
					message_1 = pad16(message)
					sock.send('E'+base64.b64encode(ACTIVE_CONNECTIONS_KEYRING_AES[fd][0].encrypt(message_1)))
					print "\n[*] encrypting using AES key for connection {}.".format(fd)
				# RSA
				elif fd in ACTIVE_CONNECTIONS_KEYRING:
					current_pub_key = ACTIVE_CONNECTIONS_KEYRING[fd]
					print "\n[*] encrypting using pubkey {} for connection {}.".format(current_pub_key, fd)
					sock.send( 'E'+encrypt(message_1,current_pub_key) )
				else:
					sock.send(message_1)
			except:
				# this exception handles broken connections which
				# are just assumed to be closed by client.
				fd = sock.fileno()
				sock.close()
				ACTIVE_CONNECTIONS_LIST.remove(sock)
				del ACTIVE_CONNECTIONS_KEYRING[fd]
				del ACTIVE_CONNECTIONS_KEYRING_AES[fd]



if __name__=="__main__":
	DEBUG = 0
	# DEFINITIONS (global := capitalization)
	NO_ENCRYPTION = 0
	ACTIVE_CONNECTIONS_LIST = []
	ACTIVE_CONNECTIONS_KEYRING = {}
	ACTIVE_CONNECTIONS_KEYRING_AES = {}
	BUFFER_RECV = 16384
	PORT = 1337
	IP = '0.0.0.0'
	KEY_SIZE = 24
	
	if len(sys.argv) > 1:
		if sys.argv[1] == 'NO_ENCRYPTION':	
			NO_ENCRYPTION = 1

	server_public, server_private = generate_key_pair(KEY_SIZE)

	public_message = 'PUBKEY200 '+ str(server_public.n) + ' ' + str(server_public.e)	

	master_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	
	# needed?
	master_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	master_socket.bind((IP, PORT))
	master_socket.listen(10)

	# add master socket to active connections list A(readable sockets)
	ACTIVE_CONNECTIONS_LIST.append(master_socket)
	print "\n[*] started chat server on port {}.".format(PORT)


	cprint(figlet_format('NARCS\n SERVER', font='colossal'), 'yellow', attrs=['bold'])

	if NO_ENCRYPTION:
		print "*** WARNING: running in plaintext mode (no encryption used). ***"

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
				print "\n[+] client <%s, %s> has connected. Added to active connections list." % addr
				
					
				# [1a] send server public key to new client:
				socketfd.send(public_message)
				# announce client entry to room.
				m = "\n{} HAS ENTERED THE ROOM.\n".format(addr)
				broadcast_more_like_breadcast(socketfd, m)

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
							key_iv_client = decrypt(' '.join(data_tok[1:]), server_private)
							if DEBUG:
								print '1a - decrypted: {}'.format(key_iv_client)
							key_iv_client = key_iv_client.split('@!delim!@')
							if DEBUG:
								print '1b - split: {}'.format(key_iv_client)
							key_client = key_iv_client[0]
							if DEBUG:
								print '2 - key len: {}'.format(len(key_client))
							iv_client = key_iv_client[1]
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
							if DEBUG:
								test 	= 'dog'
								entest 	= ACTIVE_CONNECTIONS_KEYRING_AES[int(fd)][0].encrypt(pad16(test))
								print 'ISSUE WITH ENCRYPTION?'
								detest 	= ACTIVE_CONNECTIONS_KEYRING_AES[int(fd)][1].decrypt(entest)
								print "detest type: {}".format(type(detest))
								detestupad	= depad16(detest)
								print "SANITY CHECK: [{}] ENCRYPTS TO [{}]".format(test, entest)
								print "which decrypts to [{}]".format(detestupad)
		
							print "\n[*] GOT AES KEY."

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
									if DEBUG:
										print "broadcasting [{}] using AES keyring.".format(de_message) 
									broadcast_more_like_breadcast(socc, "\r"+str(socc.getpeername())+" -> "+ de_message )
								else:
									broadcast_more_like_breadcast(socc, "\r"+str(socc.getpeername())+" -> "+ decrypt(data[1:], server_private))
							else:
								broadcast_more_like_breadcast(socc, "\r"+str(socc.getpeername())+" -> "+ data)

				except:
					en_message = "\n[-] client <{}> has LEFT the room.\n".format(addr)
					broadcast_more_like_breadcast(socc,en_message) 
					print "\n[-]client <%s:%s> has gone offline.\n" % addr
					fd = socc.fileno()
					socc.close()
					ACTIVE_CONNECTIONS_LIST.remove(socc)
					del ACTIVE_CONNECTIONS_KEYRING[fd]
					del ACTIVE_CONNECTIONS_KEYRING_AES[fd]	
					continue

			
	master_socket.close()


#if __name__ == "__main__": main()
