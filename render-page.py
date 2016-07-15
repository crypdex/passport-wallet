#!/usr/bin/env python

# render an encrypted paper wallet for a single crypto-currency address


import sys, os, argparse, getpass, time, hashlib
from random import randint
from common import logger, cmd, pad, unwrap, break_string, positive_integer
from common import default_iterations, default_background, salt_length_words
from Crypto.Cipher import AES
from PIL import Image


# command line arguments
parser = argparse.ArgumentParser(description='Generate a secure, mnemonic paper wallet for a crypto-currency address')
parser.add_argument('-s', '--symbol', help='crypto-currency symbol', nargs=1, required=True)
parser.add_argument('-n', '--name', help='crypto-currency name (default is name lookup by symbol)', nargs=1, required=False)
parser.add_argument('-a', '--address', help='public address', nargs=1, required=True)
parser.add_argument('-k', '--privkey', help='private key', nargs=1, required=True)
parser.add_argument('-i', '--icon', help='crypto-currency icon file (default ./images/[symbol]-logo.png)', nargs=1, required=False)
parser.add_argument('-t', '--iterations', help='HASH iterations (default {})'.format(default_iterations), nargs=1, type=positive_integer, default=default_iterations, required=False)
parser.add_argument('-b', '--background', help='background image (default "{}")'.format(default_background), nargs=1, default=default_background, required=False)
parser.add_argument('-p', '--password', help='encryption password (user is prompted if not present)', nargs=1, required=False)
parser.add_argument('-o', '--output', help='output filename (default "./passport-page-[symbol].png")', nargs=1, required=False)
parser.add_argument('-c', '--comment', help='add an optional comment', nargs=1, required=False)
args = vars(parser.parse_args())


# currency symbol
symbol = args['symbol'][0].upper()
logger.debug('SYMBOL {}'.format(symbol))


# currency name
cname = None
explorer = None
with open('assets.csv') as fp:
    lines = fp.readlines()
    for line in lines:
        sym, name, link = line.split(',')
        if (sym.upper() == symbol.upper()):
            cname = name.strip()
            if len(link.strip()) > 0:
                explorer = link.strip()
                
if args['name'] is not None:
    cname = args['name'][0]    

if cname is not None:
    logger.debug('NAME {}'.format(cname))
else:
    logger.critical('could not determine currency name for symbol {}'.format(symbol))
    exit(1)


# public address
address = args['address'][0]
logger.debug('ADDRESS {}'.format(address))


# private key
privkey = args['privkey'][0]


# block explorer
link = None
if explorer is not None:
    link = explorer.format(address)
    logger.debug('EXPLORER {}'.format(link))
else:
    logger.warning('no block explorer found for currency {}'.format(symbol))
    link = address 


# validate icon file
file_icon = None
if args['icon'] is not None:
    (file_icon,) = args['icon']
else:
    file_icon = './images/icon-{}.png'.format(symbol.lower())

if (os.path.isfile(file_icon)):
    logger.debug('ICON FILE {}'.format(file_icon))
else:
    logger.critical('icon file does not exist: {}'.format(file_icon))
    exit(1)


# hash iterations
hash_iterations = unwrap(args['iterations'])
logger.debug('ITERATIONS {:,}'.format(hash_iterations))


# background image
file_background = unwrap(args['background'])
if (os.path.isfile(file_background)):
    logger.debug('BACKGROUND {}'.format(file_background))
else:
    logger.critical('background file does not exist: {}'.format(file_background))
    exit(1)


# ask for password if not present
pwd = None
if args['password'] is not None:
    pwd = args['password'][0]
else:
    matching = False
    while not matching:
        pwd = getpass.getpass('encryption password:')
        verify = getpass.getpass('verify password:')
        if pwd == verify:
            matching = True
        else:
            logger.error('passwords do not match')


# output filename
file_output = None
if args['output'] is not None:
    file_output = args['output'][0]
else:
    file_output = 'passport-page-{}.png'.format(symbol.lower())
logger.debug('OUTPUT FILE {}'.format(file_output))


# comment field
comment = None
if args['comment'] is not None:
    comment = args['comment'][0]
    logger.debug('COMMENT {}'.format(comment))
else:
    logger.debug('no comment present')


#
# generate passport image
#

# compute average color of icon
im = Image.open(file_icon)
xs,ys = im.size
count = 0.0
rsum = 0.0
gsum = 0.0
bsum = 0.0
for x in range(xs):
    for y in range(ys):
        (r,g,b,a) = im.getpixel((x,y))
        if (r>0) and (g>0) and (b>0):
            rsum += r
            gsum += g
            bsum += b
            count += 1

ravg = int(round(rsum / count))
gavg = int(round(gsum / count))
bavg = int(round(bsum / count))

# light and dark compliments
rgb_avg = hex(ravg)[2:].upper() + hex(gavg)[2:].upper() + hex(bavg)[2:].upper()
logger.debug('RGB_AVG #' + rgb_avg)

darkness = 2.0
rgb_dark = hex(int(ravg/darkness))[2:].upper() + hex(int(gavg/darkness))[2:].upper() + hex(int(bavg/darkness))[2:].upper()
logger.debug('RGB_DARK #' + rgb_dark)

lightness = 2.0
rgb_light = hex(256-int((256-ravg)/lightness))[2:].upper() + hex(256-int((256-gavg)/lightness))[2:].upper() + hex(256-int((256-bavg)/lightness))[2:].upper()
logger.debug('RGB_LIGHT #' + rgb_light)


# create coin graphic
icon_width = 150
file_logo_resized = '/tmp/passport-resized-icon-{}.png'.format(os.getpid())
dimensions = '{}x{}!'.format(icon_width, icon_width)
cmd(['convert', file_icon, '-resize', dimensions, file_logo_resized])


# add coin graphic to background
position = '+35+25'
cmd(['composite', '-geometry', position, file_logo_resized, file_background, file_output])
os.remove(file_logo_resized)


# add currency symbol header
size = str(192 - (16 * len(symbol)))
position = '+200+150'
font = 'DejaVu-Sans-Bold'
cmd(['convert', file_output, '-font', font, '-fill', '#{}'.format(rgb_light), '-pointsize', size, '-annotate', position, symbol, file_output])


# currency name
size = '18'
position = '+265+240'
font = 'Helvetica-Bold'
txt = "Currency"
cmd(['convert', file_output, '-font', font, '-fill', '#{}'.format(rgb_dark), '-pointsize', size, '-annotate', position, txt, file_output])

position = '+360+240'
font = 'Courier-Bold'
txt = cname
cmd(['convert', file_output, '-font', font, '-fill', '#{}'.format(rgb_dark), '-pointsize', size, '-annotate', position, txt, file_output])


# public address
position = '+265+265'
font = 'Helvetica-Bold'
txt = "Address"
cmd(['convert', file_output, '-font', font, '-fill', '#{}'.format(rgb_dark), '-pointsize', size, '-annotate', position, txt, file_output])

position = '+360+265'
font = 'Courier-Bold'
txt = '\n'.join(break_string(address, 17))
cmd(['convert', file_output, '-font', font, '-fill', '#{}'.format(rgb_dark), '-pointsize', size, '-annotate', position, txt, file_output])


# creation date
position = '+265+315'
font = 'Helvetica-Bold'
txt = "Created"
cmd(['convert', file_output, '-font', font, '-fill', '#{}'.format(rgb_dark), '-pointsize', size, '-annotate', position, txt, file_output])

position = '+360+315'
font = 'Courier-Bold'
localtime = time.localtime()
txt = time.strftime("%Y-%m-%d", localtime)
cmd(['convert', file_output, '-font', font, '-fill', '#{}'.format(rgb_dark), '-pointsize', size, '-annotate', position, txt, file_output])


# optional note
if (comment is not None):
    position = '+265+345'
    font = 'Helvetica-Bold'
    txt = "Notes"
    cmd(['convert', file_output, '-font', font, '-fill', '#{}'.format(rgb_dark), '-pointsize', size, '-annotate', position, txt, file_output])

    position = '+360+345'
    font = 'Courier-Bold'
    txt = comment
    cmd(['convert', file_output, '-font', font, '-fill', '#{}'.format(rgb_dark), '-pointsize', size, '-annotate', position, txt, file_output])


# qr code drop shadow
qr_width = icon_width * 1.25
position = '+39+199'
size = '{}x{}'.format(qr_width+6, qr_width+6)
file_shadow = '/tmp/passport-qr-shadow-{}.png'.format(os.getpid())
cmd(['convert', '-size', size, 'xc:#{}'.format(rgb_light), '-fill' , 'none', '-stroke', 'black', file_shadow])
cmd(['composite', '-geometry', position, file_shadow, file_output, file_output])


# make qr code
file_qr = '/tmp/passport-qr-code-{}.png'.format(os.getpid())
position = '+40+200'
cmd(['qrencode', '--foreground', rgb_dark, '-o', file_qr, explorer.format(address)])
cmd(['convert', file_qr, '-resize', '{}x{}'.format(qr_width, qr_width), file_qr])
cmd(['composite', '-geometry', position, file_qr, file_output, file_output])
os.remove(file_qr)


#
# word sequence = BIP39(AES(private_key, SHA256^iterations(password + salt)))
#


# load bip39 dict
bip39 = []
with open('words-bip39.csv') as fp:
    lines = fp.readlines()
bip39 = [line.strip() for line in lines]

    
# generate salt
seed_list = [ bip39[randint(0,len(bip39)-1)] for i in range(salt_length_words) ]
seed = ' '.join(seed_list)
logger.debug('SEED [{}] {}'.format(len(seed_list), seed))
hash = hashlib.sha256(seed).hexdigest()
logger.debug('HASH [{}] {}'.format(len(hash), hash))
salt = hash[:16]
logger.debug('SALT [{}] {}'.format(len(salt), salt))


# add divider graphic
divider_width = 400
position = '+90+425'
file_divider = './images/divider.png'
file_divider_resized = '/tmp/passport-resized-divider.png'.format(os.getpid())
dimensions = '{}x{}'.format(divider_width, divider_width)
cmd(['convert', file_divider, '-resize', dimensions, '-fuzz', '100%', '-fill', '#{}'.format(rgb_light), '-opaque', 'white', file_divider_resized])
cmd(['composite', '-geometry', position, file_divider_resized, file_output, file_output])
os.remove(file_divider_resized)


# stretch key
h = pwd + salt
start = time.time()
logger.debug('stretching key...')

for i in xrange(hash_iterations):
    h = hashlib.sha256(h).hexdigest()
    if ((i+1) % 1000000) == 0:
        elapsed = time.time() - start
        logger.debug('{}m hashes in {} seconds'.format(round(i/1000000.0, 1), round(elapsed, 1)))

elapsed = time.time() - start
logger.debug('{}m hashes in {} seconds'.format(round(i/1000000.0, 1), round(elapsed, 1)))

hashed_password = h
logger.debug('HASH length {} bytes'.format(len(hashed_password)))


# 32-byte AES key
aes_key = hashed_password[:32]
logger.debug('KEY length {}'.format(len(aes_key)))


# pad input text
payload = pad(privkey, 16)
logger.debug('DATA length {:,} bytes'.format(len(payload), payload))


# AES encrypt private key with hashed password
iv = salt  # shared nonce; salt for key stretching is also the AES init vector
e = AES.new(aes_key, AES.MODE_CBC, iv)
cipher_text = e.encrypt(payload)
logger.debug('CIPHERTEXT length {} bytes'.format(len(cipher_text)))


# sanity check: decrypt back again
decryption_suite = AES.new(aes_key, AES.MODE_CBC, salt)
plain_text = decryption_suite.decrypt(cipher_text)
if plain_text == payload:
    logger.debug('DECRYPTION sanity check passed')
else:
    logger.critical('DECRYPTION sanity check failed!')
    exit(1)


# convert 8-bit ciphertext into 11-bit chunks
i = 0
chunks = []
word_cursor = 0
word_value = 0

for byte in bytes(cipher_text):
    o = ord(byte)

    for bit in range(8):
        if (i - word_cursor) >= 11:
            chunks.append(word_value)
            word_cursor = i
            word_value = 0

        if o & 2**bit:
            word_value += int(2**(i-word_cursor))

        i += 1

chunks.append(word_value) # remaining bits


# convert 11-bit words to English words via BIP39
column_width = 45
words = [bip39[i].strip() for i in chunks]


# prepend salt to word seq
words = seed_list + words

# insert newlines 
i = 0
txt = ''
for word in words:
    i += len(word) + 1
    if i > column_width:
        txt += '\\n'
        i = len(word) + 1
    txt += word + ' '


# add words to page
size = '18'
position = '+60+525'
font = 'Courier-Bold'
cmd(['convert', file_output, '-font', font, '-fill', '#{}'.format(rgb_dark), '-pointsize', size, '-annotate', position, txt, file_output])

logger.info('wrote {}'.format(file_output))
