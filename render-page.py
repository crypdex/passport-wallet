#!/usr/bin/env python


# render a page of a passport wallet
import sys, os, argparse, getpass, time, hashlib
from subprocess import Popen, PIPE
from Crypto.Cipher import AES
from PIL import Image
from common import default_iterations, default_background


# configure logging
import logging
logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', level=logging.INFO)


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
def multiline(string, width):
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
logging.debug('SYMBOL {}'.format(symbol))


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
    logging.debug('NAME {}'.format(cname))
else:
    logging.critical('Could not determine currency name for symbol {}'.format(symbol))
    exit(1)


# public address
address = args['address'][0]
logging.debug('ADDRESS {}'.format(address))


# private key
privkey = args['privkey'][0]


# block explorer
link = None
if explorer is not None:
    link = explorer.format(address)
    logging.debug('EXPLORER {}'.format(link))
else:
    logging.warning('No block explorer found for currency {}'.format(symbol))
    link = address 


# validate icon file
file_icon = None
if args['icon'] is not None:
    (file_icon,) = args['icon']
else:
    file_icon = './images/icon-{}.png'.format(symbol.lower())

if (os.path.isfile(file_icon)):
    logging.debug('ICON FILE {}'.format(file_icon))
else:
    logging.critical('Icon file does not exist: {}'.format(file_icon))
    exit(1)


# hash iterations
hash_iterations = unwrap(args['iterations'])
logging.debug('ITERATIONS {:,}'.format(hash_iterations))


# background image
file_background = unwrap(args['background'])
if (os.path.isfile(file_background)):
    logging.debug('BACKGROUND {}'.format(file_background))
else:
    logging.critical('Background file does not exist: {}'.format(file_background))
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
            logging.error('Passwords do not match')


# output filename
file_output = None
if args['output'] is not None:
    file_output = args['output'][0]
else:
    file_output = 'passport-page-{}.png'.format(symbol.lower())
logging.debug('OUTPUT FILE {}'.format(file_output))


# comment field
comment = None
if args['comment'] is not None:
    comment = args['comment'][0]
    logging.debug('COMMENT {}'.format(comment))
else:
    logging.debug('No comment present')


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
logging.debug('RGB_AVG #' + rgb_avg)

darkness = 2.5
rgb_dark = hex(int(ravg/darkness))[2:].upper() + hex(int(gavg/darkness))[2:].upper() + hex(int(bavg/darkness))[2:].upper()
logging.debug('RGB_DARK #' + rgb_dark)

lightness = 2.0
rgb_light = hex(256-int((256-ravg)/lightness))[2:].upper() + hex(256-int((256-gavg)/lightness))[2:].upper() + hex(256-int((256-bavg)/lightness))[2:].upper()
logging.debug('RGB_LIGHT #' + rgb_light)


# create coin graphic
icon_width = 150
file_resized = '/tmp/passport-resized-icon-{}.png'.format(os.getpid())
dimensions = '{}x{}!'.format(icon_width, icon_width)
cmd(['convert', file_icon, '-resize', dimensions, file_resized])


# add coin graphic to background
position = '+35+25'
cmd(['composite', '-geometry', position, file_resized, file_background, file_output])
os.remove(file_resized)


# add currency symbol header
size = '128'
position = '+200+160'
font = 'DejaVu-Sans-Bold'
cmd(['convert', file_output, '-font', font, '-fill', '#{}'.format(rgb_light), '-pointsize', size, '-annotate', position, symbol, file_output])


# currency name
size = '18'
position = '+245+240'
font = 'Helvetica-Bold'
txt = "Currency"
cmd(['convert', file_output, '-font', font, '-fill', '#{}'.format(rgb_dark), '-pointsize', size, '-annotate', position, txt, file_output])

position = '+340+240'
font = 'Courier-Bold'
txt = cname
cmd(['convert', file_output, '-font', font, '-fill', '#{}'.format(rgb_dark), '-pointsize', size, '-annotate', position, txt, file_output])


# public address
position = '+245+265'
font = 'Helvetica-Bold'
txt = "Address"
cmd(['convert', file_output, '-font', font, '-fill', '#{}'.format(rgb_dark), '-pointsize', size, '-annotate', position, txt, file_output])

position = '+340+265'
font = 'Courier-Bold'
txt = '\n'.join(multiline(address, 17))
cmd(['convert', file_output, '-font', font, '-fill', '#{}'.format(rgb_dark), '-pointsize', size, '-annotate', position, txt, file_output])


# creation date
position = '+245+315'
font = 'Helvetica-Bold'
txt = "Created"
cmd(['convert', file_output, '-font', font, '-fill', '#{}'.format(rgb_dark), '-pointsize', size, '-annotate', position, txt, file_output])

position = '+340+315'
font = 'Courier-Bold'
localtime = time.localtime()
txt = time.strftime("%Y-%m-%d", localtime)
cmd(['convert', file_output, '-font', font, '-fill', '#{}'.format(rgb_dark), '-pointsize', size, '-annotate', position, txt, file_output])


# optional note
if (comment is not None):
    position = '+245+345'
    font = 'Helvetica-Bold'
    txt = "Notes"
    cmd(['convert', file_output, '-font', font, '-fill', '#{}'.format(rgb_dark), '-pointsize', size, '-annotate', position, txt, file_output])

    position = '+340+345'
    font = 'Courier-Bold'
    txt = comment
    cmd(['convert', file_output, '-font', font, '-fill', '#{}'.format(rgb_dark), '-pointsize', size, '-annotate', position, txt, file_output])


# make qr code
w = icon_width * 1.25
file_qr = '/tmp/passport-qr-code-{}.png'.format(os.getpid())
position = '+40+200'

cmd(['qrencode', '--foreground', rgb_dark, '-o', file_qr, explorer.format(address)])
cmd(['convert', file_qr, '-resize', '{}x{}'.format(w,w), file_qr])
cmd(['composite', '-geometry', position, file_qr, file_output, file_output])
os.remove(file_qr)


#
# word sequence = BIP39(AES(private_key, SHA256^iterations(password + salt)))
#

# choose salt
salt = address[1:17]
logging.debug('SALT [{}] {}'.format(len(salt), salt))


# description
size = '16'
position = '+30+450'
font = 'Helvetica-Bold'
txt = 'BIP39(AES(pkey,SHA256^{}(pass+\'{}\'))) ='.format(hash_iterations, salt)
cmd(['convert', file_output, '-font', font, '-fill', '#{}'.format(rgb_dark), '-pointsize', size, '-annotate', position, txt, file_output])


# stretch key
h = pwd + salt
start = time.time()

for i in xrange(hash_iterations):
    h = hashlib.sha256(h).hexdigest()
    if ((i+1) % 1000000) == 0:
        elapsed = time.time() - start
        logging.debug('{}m hashes in {} seconds'.format(round(i/1000000.0, 1), round(elapsed, 1)))

elapsed = time.time() - start
logging.debug('{}m hashes in {} seconds'.format(round(i/1000000.0, 1), round(elapsed, 1)))

hashed_password = h
logging.debug('HASH [{}] {}'.format(len(hashed_password), hashed_password))


# 32-byte AES key
aes_key = hashed_password[-32:]
logging.debug('AES_KEY [{}] {}'.format(len(aes_key), aes_key))


# pad input text
payload = pad(privkey, 16)
logging.debug('PAYLOAD [{}] {}'.format(len(payload), payload))


# AES encrypt private key with hashed password
e = AES.new(aes_key, AES.MODE_CBC, salt)
cipher_text = e.encrypt(payload)
logging.debug('CIPHER_TEXT length {} bytes'.format(len(cipher_text)))


# sanity check: decrypt
decryption_suite = AES.new(aes_key, AES.MODE_CBC, salt)
plain_text = decryption_suite.decrypt(cipher_text)
if plain_text == payload:
    logging.debug('Decryption suceeded')
else:
    logging.critical('Decryption sanity check failed!')
    exit(1)


# convert 8-bit cipher text into 11-bit chunks
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


# load bip39 dict
d = []
with open('words-bip39.csv') as fp:
    d = fp.readlines()


# create word list
column_width = 45
words = [d[i].strip() for i in chunks]

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
position = '+50+510'
font = 'Courier-Bold'
cmd(['convert', file_output, '-font', font, '-fill', '#{}'.format(rgb_dark), '-pointsize', size, '-annotate', position, txt, file_output])

logging.info('Wrote {}'.format(file_output))
