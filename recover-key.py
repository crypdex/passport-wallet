#!/usr/bin/env python


# input words
# input password
# print result

#import sys, os, argparse, getpass, time, hashlib, random
#from PIL import Image
#from subprocess import Popen, PIPE
from Crypto.Cipher import AES

import sys, time, hashlib

hash_iterations = 1000000
address = '1AmScRbGuGsYPWQNjWu7DpxYytu9yz7ZCg'
words = 'nurse purchase topple million barely female shallow subway history saddle broken twist stage fantasy earth morning ripple deliver vessel dynamic extra change matrix era hill ketchup number museum magnet gap area dwarf hero parrot edge flame million survey sustain hub rigid cancel away twenty arrive ugly acoustic'
pwd = 'foobar'

print 'ADDRESS:', address
print 'WORDS:', words
print 'PWD:', pwd

# convert words to 11-bit numbers
with open('words-bip39.csv') as fp:
    lines = fp.readlines()

bip39_words = [line.strip() for line in lines]
indexes = [bip39_words.index(word) for word in words.split()]


# convert 11-bit chunks into 8-bit cyphertext
i = 0
cipher_text = ''
byte_cursor = 0
byte_value = 0

for index in indexes:
    for bit in range(11):
        if (i - byte_cursor) >= 8:
            cipher_text += chr(byte_value)
            byte_cursor = i
            byte_value = 0

        if index & 2**bit:
            byte_value += int(2**(i-byte_cursor))

        i += 1
#cipher_text += chr(byte_value)

print 'cipher_text', '[{}]'.format(cipher_text), len(cipher_text), type(cipher_text)

def bits(s):
    bytes = [ord(b) for b in s]
    for b in bytes:
        for i in xrange(8):
            if (2**i & b):
                sys.stdout.write('X')
            else:
                sys.stdout.write('O')
    sys.stdout.write('\n')

bits(cipher_text)

# stretch key
h = pwd + address
start = time.time()
sys.stdout.write('key stretching')

for i in xrange(hash_iterations):
    h = hashlib.sha256(h).hexdigest()

    if (i % 100000) == 0:
        sys.stdout.write('.')
        sys.stdout.flush()

elapsed = time.time() - start
print '\n{:,}m SHA256 iterations in {} seconds'.format(round(i/1000000.0, 1), round(elapsed, 1))

hashed_password = h
print 'hash[{}] {}'.format(len(hashed_password), hashed_password)

aes_key = hashed_password[-32:]
print 'aes_key [{}] {}'.format(len(aes_key), aes_key)

salt = address[1:17]
print 'salt[{}] {}'.format(len(salt), salt)

d = AES.new(aes_key, AES.MODE_CBC, salt)
plain_text = d.decrypt(cipher_text).strip()
print 'plain_text', '[{}]'.format(plain_text), len(plain_text), type(plain_text)


