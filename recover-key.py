#!/usr/bin/env python

import sys, argparse, time, hashlib, getpass, pyscrypt, logging
from Crypto.Cipher import AES
from common import logger, salt_length_words
from common import words2bytes, scrypt_N, scrypt_r, scrypt_p


logger.setLevel(logging.INFO)


# command line arguments
parser = argparse.ArgumentParser(description='Decrypt a passport wallet from word sequence and password')
parser.add_argument('-v', '--verbose', help='show verbose output', action='store_true', required=False)
args = vars(parser.parse_args())

if (args['verbose']):
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)


# load BIP39 dictionary
with open('words-bip39.csv') as fp:
    lines = fp.readlines()
bip39_words = [line.strip() for line in lines]


# get user input
words_input = raw_input('WORDS:').lower().split()

# validate words
pos = 1
invalid = False
for word in words_input:
    try:
        check = bip39_words.index(word)
    except ValueError:
        logger.error('invalid word in position {}: {}'.format(pos, word))
        invalid = True
    pos += 1

if invalid:
    exit(0)


# generate nonces
seed_list = words_input[:salt_length_words]
seed = ' '.join(seed_list)
logger.debug('SEED [{}] {}'.format(len(seed), seed))
seed_hash = hashlib.sha256(seed).hexdigest()
salt = seed_hash[:8]
logger.debug('SALT [{}] {}'.format(len(salt), salt))
iv = seed_hash[:16]
logger.debug('IVEC [{}] {}'.format(len(iv), iv)) 


# convert words to 11-bit numbers
words = words_input[salt_length_words:]
indexes = [bip39_words.index(word) for word in words]


# convert 11-bit words to ciphertext byte array
ciphertext = words2bytes(words)
clen = len(ciphertext)
logger.debug('CIPHERTEXT length {} bytes'.format(clen))
if (clen % 16) != 0:
    logger.error('ciphertext length is {} but must be a multiple of 16'.format(clen))
    exit(0)


# stretch key
pwd = getpass.getpass('PASSWORD:')
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
