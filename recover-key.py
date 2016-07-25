#!/usr/bin/env python

import sys, time, hashlib, getpass, pyscrypt
from Crypto.Cipher import AES
from common import logger, salt_length_words
from common import words2bytes, scrypt_N, scrypt_r, scrypt_p


# get user input
words_input = raw_input('WORDS:').lower().split()
pwd = getpass.getpass('PASSWORD:')


# generate nonces
seed_list = words_input[:salt_length_words]
seed = ' '.join(seed_list)
logger.debug('SEED [{}] {}'.format(len(seed), seed))
seed_hash = hashlib.sha256(seed).hexdigest()
salt = seed_hash[:8]
logger.debug('SALT [{}] {}'.format(len(salt), salt))
iv = seed_hash[:16]
logger.debug('IVEC [{}] {}'.format(len(iv), iv)) 


# load BIP39 dictionary
with open('words-bip39.csv') as fp:
    lines = fp.readlines()
bip39_words = [line.strip() for line in lines]

    
# convert BIP39 words to 11-bit numbers
words = words_input[salt_length_words:]
indexes = [bip39_words.index(word) for word in words]


# convert 11-bit words to ciphertext byte array
ciphertext = words2bytes(words)
logger.debug('CIPHERTEXT length {} bytes'.format(len(ciphertext)))


# stretch key
start = time.time()
logger.debug('stretching key ...')
hashed_password = pyscrypt.hash(password=pwd, salt=salt, N=scrypt_N, r=scrypt_r, p=scrypt_p, dkLen = 32)
hashed_hex = hashed_password.encode('hex')
elapsed = time.time() - start
logger.debug('scrypt(N={},r={},p={}) took {:.1f} seconds'.format(scrypt_N, scrypt_r, scrypt_p, elapsed))
aes_key = hashed_hex[:32]
logger.debug('KEY length {} bytes'.format(len(aes_key)))


# decrypt
d = AES.new(aes_key, AES.MODE_CBC, iv)
plaintext = d.decrypt(ciphertext).strip()
logger.info('PLAINTEXT [{}] {}'.format(len(plaintext), plaintext))

