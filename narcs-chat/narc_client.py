from rsa import * 			# custom library
import socket
import select
import string
import sys
import random
import os
from Crypto.Cipher import AES
import base64

# for fancy ui ######################
from colorama import init
from termcolor import cprint
from pyfiglet import figlet_format
init(strip=not sys.stdout.isatty()) # strp colors if stdout is redir.
#####################################
'''
USER PROMPT FUNCTION
---------------------
displays user prompt. plain and simple.

'''

def prompt_display():
	#print "[you]-> ",
	sys.stdout.write("[you]-> ")
	sys.stdout.flush()

'''
WRAPPER ENCRYPT/DECRYPT FUNCTIONS <HELPER>
----------------------------------
help with encryption and decryption using assets from rsa.py
'''


def encrypt(message, pub_key):
	en_message = ''
	for c in message:
		en_message +=' ' + str( pub_key.encrypt( ord(c) ) )
	return en_message

def decrypt(message, pri_key):
	message_list = message.split(' ')
	message_list = filter(None, message_list)
	de_message = ''
	for c in message_list:
		de_message += chr( pri_key.decrypt( int(c) ) )
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

(0)	client public key and private key for CHEAP RSA are created.
	This probably should be made to only be done if pure
	RSA opetion is selected.

(1) user input determines if AES is used or pure "cheap" RSA
	for message comms.

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
		print 'error, usage is of form:\n\tpython chat_client.py hostname/IP port'
		sys.exit()
	if len(sys.argv) == 4:
		if sys.argv[3] == "NO_ENCRYPTION":
			NO_ENCRYPTION = 1
	HOST = sys.argv[1]
	PORT = int(sys.argv[2])
	IN_BUFFER = 16384
	KEY_SIZE = 24
	client_public, client_private = generate_key_pair(KEY_SIZE)
	GOTPUBKEY = 0
	SENTAES = 0
	# ask user if AES should be used.
	USE_AES = 0
	if not NO_ENCRYPTION:
		response = raw_input("-----------------------\nwould you like to use AES encryption? (y/n)\nif no, pure RSA will be used.\n-----------------------\nanswer: ")
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

	# set up WELCOME messages
	welcome_messages = [ "HOWDY.",
						"FIRE AT WILL.",
						"SOMEDAY THEY\'LL REPLY.",
						"QUICK EVERYONE HIDE.",
						"WELCOME?",
						"WELCOME BACK END-USER, WE APPRECIATE YOU.",
						"WHAT HAPPENS NarcsChat STAYS IN NarcsChat.",
						"CHATTY CHATTY BANG BANG.",
						"TRUDY HATES THIS APP.",
						"HOW MANY CHATS COULD A CHATROOM CHAT IF A CHATROOM COULD CHAT CHATS?",
						"OF COURSE IT WORKS.",
						"CHAT AWAY.",
						"SILLY TRUDY, CHATS ARE FOR KIDS!",
						"ONE SMALL STEP FOR CHAT, ONE GIANT LEAP FOR CHATROOMS.",
						"YOUR SECRET IS SAFE WITH US."
						]



	# ATTEMPT TO CONNECT TO SERVER
	try:
		print "[*] attempting to connecting to {} at port {}... ".format(HOST,PORT)
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
		n_server = int(data_tok[1])
		e_server = int(data_tok[2])
		server_public = publicKey(n = n_server, e = e_server)
		print '\n[*] received server public key.'
		GOTPUBKEY = 1
	else:
		print "ERROR: did not receive public key from server as expected"
		client_socket.close()
		sys.exit()

	
	# SEND KEY TO SERVER
	print '[*] SENDING KEY TO SERVER.'	
	if USE_AES == 0:
		#sys.stdin.readline()
		# GET PUBLIC KEY, SEND PUBLIC KEY
		print "[*] sending public key {} to server.".format(client_public)
		message = 'PUBKEY200 '+str(client_public.n)+' '+ str(client_public.e)
		if DEBUG:
			print 'sending: [{}]'.format(message)
		client_socket.send(message)
		#KEY_EXCHANGED = 1
		#sys.stdin.flush()
	# case [2b] send AES
	elif USE_AES and GOTPUBKEY:
		#sys.stdin.readline()
		print "[*] sending AES shared secret using RSA encryption."
		message = 'AESKEY200 '+ encrypt(key256 + '@!delim!@' + iv, server_public)
		if DEBUG:
			print 'sending: [{}]'.format(message)
		client_socket.send(message)
		#SENTAES = 1
		#sys.stdin.readline()


	######################################################################

	cprint(figlet_format('NARCS\n CHAT', font='speed'), 'magenta', attrs=['bold'])


	print "--------------------------------------------\n{}\n--------------------------------------------\n".format(welcome_messages[random.randint(0, len(welcome_messages)-1 )])
	
	
	sys.stdin.flush()

	while True:
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
						print "NOT DATA in {} with data [{}]".format(socc.fileno(), data)
					print "\n[*] connection closed--disconnected from chat server."
					sys.exit()
				else:

					data_tok = data.split(' ')

					if data[0] != 'E':
						sys.stdout.write(data)
					else:
						if USE_AES:
							sys.stdout.write( depad16( de_object.decrypt( base64.b64decode(data[1:]) ) ) ) 
						else:
							sys.stdout.write(decrypt(data[1:], client_private))
					prompt_display()

			# case [2] user submitted message.
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


