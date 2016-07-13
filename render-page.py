#!/usr/bin/env python

import sys, os, argparse, getpass, time, hashlib, random
from PIL import Image
from subprocess import Popen, PIPE
from Crypto.Cipher import AES

hash_iterations = 2400000
text_width = 45
default_rounds = 14
default_background = './images/passport-background-lines.png'


localtime   = time.localtime()
print time.strftime('%Y-%m-%d %H:%M:%S', localtime)


# execute shell command
def cmd(str):
    sys.stderr.write(' '.join(str) + '\n')
    process = Popen(str, stderr=PIPE, stdout=PIPE)
    outdata, errdata = process.communicate()
    if len(outdata.strip()) > 0:
        print outdata
    if len(errdata.strip()) > 0:
        print errdata
    if (process.returncode):
        exit(1)


def chunkstring(string, length):
    return (string[0+i:length+i] for i in range(0, len(string), length))


def integer(val):
    try:
        return int(val)
    except:
        msg = '{} is not an integer'.format(val)
        raise argparse.ArgumentTypeError(msg)
    

def positive_integer(val):
    if (integer(val) and val > 0):
        return val
    else:
        msg = '{} is not positive'.format(val)
        raise argparse.ArgumentTypeError(msg)
    

parser = argparse.ArgumentParser(description='Generate a secure, mnemonic paper wallet for a crypto-currency')
parser.add_argument('-s', '--symbol', help='crypto-currency symbol', nargs=1, required=True)
parser.add_argument('-a', '--address', help='public address', nargs=1, required=True)
parser.add_argument('-k', '--privkey', help='private key', nargs=1, required=True)
parser.add_argument('-n', '--name', help='crypto-currency name (can override table lookup)', nargs=1, required=False)
parser.add_argument('-i', '--icon', help='crypto-currency icon file (default images/[symbol]-logo.png)', nargs=1, required=False)
parser.add_argument('-r', '--rounds', help='bcrypt rounds (default {})'.format(default_rounds), nargs=1, type=positive_integer, default=default_rounds, required=False)
parser.add_argument('-b', '--background', help='background image (default "{}")'.format(default_background), nargs=1, default=default_background, required=False)
parser.add_argument('-p', '--password', help='encryption password (you will be prompted if not provided)', nargs=1, required=False)
parser.add_argument('-o', '--output', help='output filename for PNG file (default [symbol]-page.png', nargs=1, required=False)
parser.add_argument('-c', '--comment', help='add an optional comment', nargs=1, required=False)
args = vars(parser.parse_args())


# dump args
for k in args.keys():
    v = args[k]
    print k, args[k]


# currency symbol
symbol = args['symbol'][0]
print 'symbol', symbol


# currency name
cname = None
if args['name'] is not None:
    cname = args['name'][0]
    
else:
    with open('assets.csv') as fp:
        lines = fp.readlines()
        for line in lines:
            sym, name, link = line.split(',')
            if (sym.upper() == symbol.upper()):
                cname = name.strip()
                explorer = link

if cname is not None:
    print 'Currency name:', cname
else:
    print 'could not determine currency name for symbol {}'.format(symbol)
    exit(0)


# validate icon file
icon_file = None
if args['icon'] is not None:
    (icon_file,) = args['icon']
else:
    icon_file = './images/icon-{}.png'.format(symbol.lower())

print 'icon_file', icon_file
if (os.path.isfile(icon_file)):
    print 'found icon file {}'.format(icon_file)
else:
    print 'could not find icon file {}'.format(icon_file)
    exit(0)

    
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
            print 'passwords do not match'

print 'PWD = {}'.format(pwd)


ofile = None
if args['output'] is not None:
    ofile = args['output'][0]
    
else:
    ofile = 'passport-{}.png'.format(symbol.lower())

print 'Output file: {}'.format(ofile)


file_background = args['background']
print 'Background file: {}'.format(file_background)


address = args['address'][0]
print 'Address: {}'.format(address)


comment = None
if args['comment'] is not None:
    comment = args['comment'][0]

privkey = args['privkey'][0]


# compute average color of icon
im = Image.open(icon_file)
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

print 'AVG COLOR [R:{} G:{} B:{}]'.format(ravg, gavg, bavg)
rgb_avg = hex(ravg)[2:].upper() + hex(gavg)[2:].upper() + hex(bavg)[2:].upper()

darkness = 2.5
rgb_dark = hex(int(ravg/darkness))[2:].upper() + hex(int(gavg/darkness))[2:].upper() + hex(int(bavg/darkness))[2:].upper()

lightness = 2.0
rgb_light = hex(256-int((256-ravg)/lightness))[2:].upper() + hex(256-int((256-gavg)/lightness))[2:].upper() + hex(256-int((256-bavg)/lightness))[2:].upper()

file_resized = '/home/rseeger/Desktop/passport-resized.png'
icon_width = 150
padding = 25

col1 = padding
col2 = col1 + icon_width + padding
col3 = col2 + 100

row1 = padding
row2 = row1 + icon_width + padding

# create coin graphic
dimensions = '{}x{}!'.format(icon_width, icon_width)
cmd(['convert', icon_file, '-resize', dimensions, file_resized])

# add coin graphic to background
position = '+{}+{}'.format(col1, row1)
file_template = '/home/rseeger/Desktop/passport-template.png'
cmd(['composite', '-geometry', position, file_resized, file_background, file_template])


# add currency header
size = '128'
position = '+200+140'
font = 'DejaVu-Sans-Bold'
file_header = '/home/rseeger/Desktop/passport-header.png'

#cmd(['convert', file_template, '-font', font, '-gravity', 'center', '-fill', '#{}'.format(rgb_avg), '-pointsize', '96', '-annotate', position, symbol, file_header])

cmd(['convert', file_template, '-font', font, '-fill', '#{}'.format(rgb_light), '-pointsize', size, '-annotate', position, symbol, file_header])


txt = "Currency"
position = '+260+235'
font = 'Helvetica-Bold'
size = '16'
#font = 'Courier-Bold'
cmd(['convert', file_header, '-font', font, '-fill', '#{}'.format(rgb_dark), '-pointsize', size, '-annotate', position, txt, file_header])

txt = cname
position = '+340+235'
font = 'Courier-Bold'
cmd(['convert', file_header, '-font', font, '-fill', '#{}'.format(rgb_dark), '-pointsize', size, '-annotate', position, txt, file_header])


txt = "Address"
position = '+260+265'
font = 'Helvetica-Bold'
#font = 'Courier-Bold'
cmd(['convert', file_header, '-font', font, '-fill', '#{}'.format(rgb_dark), '-pointsize', size, '-annotate', position, txt, file_header])

txt = '\n'.join(chunkstring(address, 17))
position = '+340+265'
font = 'Courier-Bold'
cmd(['convert', file_header, '-font', font, '-fill', '#{}'.format(rgb_dark), '-pointsize', size, '-annotate', position, txt, file_header])


txt = "Created"
position = '+260+315'
font = 'Helvetica-Bold'
cmd(['convert', file_header, '-font', font, '-fill', '#{}'.format(rgb_dark), '-pointsize', size, '-annotate', position, txt, file_header])

localtime   = time.localtime()
txt = time.strftime("%Y-%m-%d", localtime)
position = '+340+315'
font = 'Courier-Bold'
cmd(['convert', file_header, '-font', font, '-fill', '#{}'.format(rgb_dark), '-pointsize', size, '-annotate', position, txt, file_header])


# optional note
if (comment is not None):
    txt = "Note"
    position = '+260+345'
    font = 'Helvetica-Bold'
    cmd(['convert', file_header, '-font', font, '-fill', '#{}'.format(rgb_dark), '-pointsize', size, '-annotate', position, txt, file_header])

    txt = comment
    position = '+340+345'
    font = 'Courier-Bold'
    cmd(['convert', file_header, '-font', font, '-fill', '#{}'.format(rgb_dark), '-pointsize', size, '-annotate', position, txt, file_header])



# make qr code
w = icon_width * 1.25
file_qr = '/home/rseeger/Desktop/passport-qr.png'
position = '+40+200'

cmd(['qrencode', '--foreground', rgb_dark, '-o', file_qr, explorer.format(address)])
#cmd(['qrencode -o file {} --foreground={}'.format(symbol, address, rgb_dark)])
cmd(['convert', file_qr, '-resize', '{}x{}'.format(w,w), file_qr])
cmd(['composite', '-geometry', position, file_qr, file_header, file_header])


# convert private key into word sequence
# words = bip39(AES(private_key, bcrypt(password, rounds)))


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

salt = address[1:17]
print 'salt[{}] {}'.format(len(salt), salt)


# add spaces to string s until its length is a multiple of m
def pad(s, m):
    pad_length = m - (len(s) % m)
    spaces = ' ' * pad_length
    return s + spaces


# 32-byte AES key
aes_key = hashed_password[-32:]
print 'aes_key [{}] {}'.format(len(aes_key), aes_key)


# pad input text
payload = pad(privkey, 16)
print 'payload [{}] {}'.format(len(payload), payload)


# AES encrypt private key with hashed password
salt = address[1:17]
e = AES.new(aes_key, AES.MODE_CBC, salt)
cipher_text = e.encrypt(payload)
print 'cipher_text', '[{}]'.format(cipher_text), len(cipher_text), type(cipher_text)


# debug: print bit representation of cipher text
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

                
# test decrypt
decryption_suite = AES.new(aes_key, AES.MODE_CBC, salt)
plain_text = decryption_suite.decrypt(cipher_text)
if plain_text == payload:
    print 'decryption suceeded'
else:
    print 'decryption failed'
    exit(1)


# convert 8-bit cipher text into 11-bit chunks
i = 0
chunks = []
word_cursor = 0
word_value = 0

for byte in bytes(cipher_text):
    o = ord(byte)
    #print 'byte_value', o

    for bit in range(8):
        if (i - word_cursor) >= 11:
            #print i, 'word_value', word_value
            chunks.append(word_value)
            word_cursor = i
            word_value = 0

        #print i, 2**bit, o & 2**bit
        if o & 2**bit:
            word_value += int(2**(i-word_cursor))
            #print 'new word_value', word_value

        i += 1
#print i, 'final_word_value', word_value
chunks.append(word_value)

# load bip39 dict
d = []
with open('words-bip39.csv') as fp:
    d = fp.readlines()

# create word list
words = [d[i].strip() for i in chunks]
print 'CHUNKS:', chunks
print 'WORDS:', ' '.join(words)

# add line breaks
i = 0
txt = '"'
for word in words:
    i += len(word) + 1
    if i > text_width:
        txt += '\n'
        i = len(word) + 1
    txt += word + ' '
txt = txt[:-1] + '"'
    

size = '18'
position = '+50+480'
font = 'Courier-Bold'
cmd(['convert', file_header, '-font', font, '-fill', '#{}'.format(rgb_dark), '-pointsize', size, '-annotate', position, txt, file_header])


txt = "BIP39(AES256(private_key, SHA256^2400000(password + salt))) ="
size = '14'
position = '+50+450'
font = 'Helvetica-Bold'
cmd(['convert', file_header, '-font', font, '-fill', '#{}'.format(rgb_dark), '-pointsize', size, '-annotate', position, txt, file_header])
