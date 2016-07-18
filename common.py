

from subprocess import Popen, PIPE


# log
import logging
logging.basicConfig(format='%(asctime)-15s %(levelname)s %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)


# config
default_iterations = 85000
default_background = './images/passport-background-lines.png'
salt_length_words = 3


# execute shell command
def cmd(str):
    logging.debug('$ ' + ' '.join(str))
    process = Popen(str, stderr=PIPE, stdout=PIPE)
    outdata, errdata = process.communicate()
    if len(outdata.strip()) > 0:
        logging.debug('STDOUT: ' + outdata)
    if len(errdata.strip()) > 0:
        logging.debug('STDERR: ' + errdata)
    if (process.returncode):
        exit(1)


# add line breaks to a string
def break_string(string, width):
    return (string[0+i:width+i] for i in range(0, len(string), width))


# validate integer type
def integer(val):
    try:
        return int(val)
    except:
        msg = '{} is not an integer'.format(val)
        raise argparse.ArgumentTypeError(msg)
    

# validate positive integer
def positive_integer(val):
    if (integer(val) and val > 0):
        return val
    else:
        msg = '{} is not positive'.format(val)
        raise argparse.ArgumentTypeError(msg)

# extract item from lists of size 1
def unwrap(obj):
    if isinstance(obj, list) and len(obj) == 1:
        (extracted,) = obj
        return extracted
    else:
        return obj

# add spaces to string s until its length is a multiple of m
def pad(s, m):
    pad_length = m - (len(s) % m)
    spaces = ' ' * pad_length
    return s + spaces


# convert byte array into 11-bit BIP39 words
def bytes2words(b):

    i = 0
    indexes = []
    word_cursor = 0
    word_value = 0

    # prepend array length in first byte
    if len(b) > 255:
        raise ValueError('byte array too large')
    b = chr(len(b)) + b

    for x in b:
        byte = ord(x)
        for bit in range(8):

            if (i-word_cursor) >= 11:
                indexes.append(word_value)
                word_cursor = i
                word_value = 0

            if byte & 2**bit:
                word_value += int(2**(i-word_cursor))

            i += 1

    indexes.append(word_value)


    # load bip39 wordlist
    bip39 = []
    with open('words-bip39.csv') as fp:
        bip39 = fp.readlines()
        bip39 = [ b.strip() for b in bip39 ]

    # convert 11-bit chunks to BIP39 english word
    words = [ bip39[i].strip() for i in indexes ]

    return words


def words2bytes(words):

    # load bip39 wordlist
    bip39 = []
    with open('words-bip39.csv') as fp:
        bip39 = fp.readlines()
        bip39 = [ b.strip() for b in bip39 ]

    # map words to 11 bit integers
    indexes = [bip39.index(word) for word in words]

    # convert to 8-bit array
    i = 0
    byte_array = ''
    byte_cursor = 0
    byte_value = 0

    for index in indexes:
        for bit in range(11):

            if (i - byte_cursor) >= 8:
                byte_array += chr(byte_value)
                byte_cursor = i
                byte_value = 0

            if index & 2**bit:
                byte_value += int(2**(i-byte_cursor))

            i += 1

    byte_array += chr(byte_value)

    # clip to original length
    blen = ord(byte_array[0])

    return byte_array[1:blen+1]


def pluralize(n):
    return '' if n == 1 else 's'
