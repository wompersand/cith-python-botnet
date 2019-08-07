import time
import sys
import hashlib

word = []

def read_file(wordlist):
    infile = open(wordlist, "rU")
    for line in infile:
        word.append(line)
        #print line
    infile.close()


def hash_crack(user_hash, options, start, stop):
    # search with all the words in wordlist
    if(options == "a"):
        time_start = time.time()
        for line in word:
            line = line.strip()
            line_hash = hashlib.md5(line).hexdigest()
            if (line_hash == user_hash.lower()):
                time_end = time.time()
                print "[*]Time: %s seconds" % round((time_end - time_start), 2)
                print "[+]Hash is: %s" % line
                return line



        time_end = time.time()
        print "[*]Time: %s seconds" % round((time_end - time_start), 2)
        return ''

    # search within given range
    elif(options == "r"):
        start = int(start)
        stop = int(stop)
        time_start = time.time()
        for line in word[start:stop]:
            line = line.strip()
            line_hash = hashlib.md5(line).hexdigest()
            if (line_hash == user_hash.lower()):
                time_end = time.time()
                print "[*]Time: %s seconds" % round((time_end - time_start), 2)
                print "[+]Hash is: %s" % line
                return line


        time_end = time.time()
        print "[*]Time: %s seconds" % round((time_end - time_start), 2)
        return ''


########################################################################
# usage: python md5_bruteforce.py filename userhash options start stop #
########################################################################

#user_hash = sys.argv[2]  # user hash
#option = sys.argv[3]    # a: search all, r give range
def crack(user_hash, a, b):
    read_file('wordlist.txt')  # wordlist
	
#if (option == 'a'):
#    start = 0
#    stop = 0
# only need to specify start and stop and option is r
    start = a     	# which line to start reading
    stop = b     	# line to stop reading
    result = hash_crack(user_hash, 'r', start, stop)
    return result
