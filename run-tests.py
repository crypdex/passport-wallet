#!/usr/bin/env python

from random import randint
from common import words2bytes, bytes2words, logger, pluralize


# load bip39 dict
d = []
with open('words-bip39.csv') as fp:
    words = fp.readlines()
bip39 = [word.strip() for word in words]


# test: bytes2words and words2bytes
# convert random byte-arrays of all sizes to words and back
byte_array = str()
for i in range(255):
    words = bytes2words(byte_array)
    result = words2bytes(words)

    if result != byte_array:
        logger.error('FAILED: byte arrays don\'t match')
        exit(1)

    byte_array += chr(randint(0,255))

logger.info('bytes to words conversion tests PASSED')

