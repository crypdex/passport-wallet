#!/usr/bin/env python

import sys, time, hashlib, getpass
from Crypto.Cipher import AES
from common import logger, default_iterations, salt_length_words


# get user input
words_input = raw_input('WORDS:').strip().lower().split()
pwd = getpass.getpass('PASSWORD:')
seed = ' '.join(words_input[0:salt_length_words])
salt = hashlib.sha256(seed).hexdigest()[:16]

words = words_input[salt_length_words:]
    
logger.debug('SEED [{}] {}'.format(len(seed), seed))
logger.debug('SALT [{}] {}'.format(len(salt), salt))

hash_iterations = default_iterations
logger.debug('ITERATIONS {:,}'.format(hash_iterations))


# load BIP39 dictionary
with open('words-bip39.csv') as fp:
    lines = fp.readlines()

    
# convert BIP39 words to 11-bit words
bip39_words = [line.strip() for line in lines]
indexes = [bip39_words.index(word) for word in words]


# convert 11-bit words to 8-bit words of ciphertext
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

logger.debug('CIPHERTEXT length {} bytes'.format(len(cipher_text)))


# stretch key
h = pwd + salt
start = time.time()
logger.debug('stretching key ...')

for i in xrange(hash_iterations):
    h = hashlib.sha256(h).hexdigest()
    if ((i+1) % 1000000) == 0:
        elapsed = time.time() - start
        logger.debug('{}m hashes in {} seconds'.format(round(i/1000000.0, 1), round(elapsed, 1)))

elapsed = time.time() - start
logger.debug('{}m hashes in {} seconds'.format(round(i/1000000.0, 1), round(elapsed, 1)))

hashed_password = h
aes_key = hashed_password[:32]


# decrypt
d = AES.new(aes_key, AES.MODE_CBC, salt)
plaintext = d.decrypt(cipher_text).strip()
logger.info('PLAINTEXT [{}] {}'.format(len(plaintext), plaintext))

