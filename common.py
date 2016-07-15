

from subprocess import Popen, PIPE


# log
import logging
logging.basicConfig(format='%(asctime)-15s %(levelname)s %(message)s', level=logging.DEBUG)
logger = logging.getLogger(__name__)


# config
default_iterations = 3620000
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
