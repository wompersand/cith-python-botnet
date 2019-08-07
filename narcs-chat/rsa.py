import random
from collections import namedtuple

'''
RSA IMPLEMENTATION FOR NET-SEC PROJECT
Nov 16. 2017

CONTENTS OF THIS FILE
---------------------
[1] public & private key custom classes
[2] get_primes_list helper function
[3] test for coprimality helper function
[4] public and private key creation

'''


'''
[1] PUBLIC & PRIVATE KEY CUSTOM CLASSES
'''
class publicKey(namedtuple('publicKey', 'n e')):
	
	__slots__ = ()
	def encrypt(self, m):
		# encrypts number m
		return pow(m, self.e, self.n) #((x**self.e) % self.n)
class privateKey(namedtuple('privateKey', 'n d')):
	
	__slots__ = ()
	def decrypt(self, c):
		# decrypts number c
		return pow(c, self.d, self.n)




'''
[2] GET PRIMES FUNCTION
-------------------
takes in start and stop values (a,b).
returns list of primes in given range (a,b).

appends 2 to list, then iterated over all odd numbers
in range testing to see if any element of the primes list being
built is a factor, if none then it appends to primes list.

'''
def get_primes_list(a,b):
	
	if a >= b:
		return []

	primes_list = [2]

	for x in range(3, b+1, 2):
		for p in primes_list:
			if x % p == 0:
				break
		else:
			primes_list.append(x)

	while primes_list and primes_list[0] < a:
		del primes_list[0]

	return primes_list

#--------------------------------------------------------------


'''
[3] COPRIME TEST FUNCTION
---------------------
boolean return value.
'''
def test_coprime(a, b):
	for x in range(2, min(a,b)+1):
		if a % x == 0 and b % x == 0:
			return False
	return True

#--------------------------------------------------------------

'''
[4] CREATE KEY PAIR
---------------
alright so here we need to specify the size of the modulo (n)
to be used. We then need to find two prime numbers that will
produce this number when multiplied.

According to [?] the n part of the key is stringer if 'p' and 'q'
are chosen to be of similar bit length. For this reason we use
range start = 1 << (length // 2 - 1) and
end = 1 << (length //2 + 1)

we then use the helper function get_primes_list to generate a list
of primes to then randomly choose from.

This function returns publicKey and privateKey objects.

(class defined in this file)
 
'''

def generate_key_pair(n_length):
	if n_length < 4:
		raise Exception('key n length too short.')
	
	# range for n
	lower_n = 1 << (n_length -1)
	upper_n = (1 << n_length) - 1
		
	# range for p & q
	a = 1 << ((n_length // 2) - 1)
	b = 1 << ((n_length // 2) + 1)

	# get a list of possible primes for p and q
	pq_primes = get_primes_list(a, b)

	# randomly select two primes from list that produce
	# a value in range (lower_n, upper_n)
	while pq_primes:
		p = random.choice(pq_primes)
		pq_primes.remove(p)
		q_possible = [q for q in pq_primes if lower_n <= p*q <= upper_n]
		if q_possible:
			q = random.choice(q_possible)
			break
	else:
		raise Exception('failed to find p and q for goven n length.')

	# now that we have a p, q and subsequently n. find suitable e.
	# e must be coprime to totient of n,
	tot_n = (p-1)*(q-1)
	for e in range(3, tot_n,2):
		if test_coprime(e, tot_n):
			break
	else:
		raise Exception('failed to find e with coprime to totient(n).')

	# now that we have p, q, n, e. we find d (private key).
	for d in range(3, tot_n, 2):
		if (d*e)% tot_n == 1:
			break
	else:
		raise Exception("failed to find d s.t. d*e == 1 mod tot(n).")
	
	# done
	n = p*q
	return  publicKey(n, e), privateKey(n, d)


#--------------------------------------------------------------

