import random
import sys
import libnum
from Crypto.Util import number
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def genPrime(bitsize=128):    # Takes the bit size argument as an input, default is 128 bits
    p = libnum.generate_prime(bitsize)
    return p

def genG(p):
    # Generate a random number smaller than p
    q = number.getRandomRange(2, p)
    # Check if q and p are coprime
    while number.GCD(q, p) != 1:
        q = number.getRandomRange(2, p)
    return q

def createH(p, g):
    # We have to choose alpha uniformly from {1, . . . , p-1}
    alpha = int(random.uniform(0, p))
    # Inbuilt python function to calculate g^alpha mod p which can handle large numbers
    h = pow(g, alpha, p)
    return h,alpha

def keyGen(h2,alpha):
    return h2**alpha 

# Now for AES

hash = "SHA256"
input_length = 16
iter_count = 65536
key_len = 32


def pad(s):
    padding_length= input_length - len(s) % input_length
    str_pad= chr(padding_length)
    padded_s= s + str_pad*padding_length
    return padded_s


def unpad(s):
    unpadded_s = s[0:-ord(s[-1:])]
    return unpadded_s


def get_secret_key(password, salt):
    pw= password.encode()
    salt= salt.encode()
    secret_key = hashlib.pbkdf2_hmac(hash, pw, salt, iter_count, key_len)
    return secret_key


def encrypt(password, salt, message):
    
    secret = get_secret_key(password, salt)
    message = pad(message)
    iv = get_random_bytes(input_length)
    cipher = AES.new(secret, AES.MODE_CBC, iv)
    cipher_bytes = base64.b64encode(iv + cipher.encrypt(message.encode("utf8")))
    return bytes.decode(cipher_bytes)


def decrypt(password, salt, cipher_text):
    secret = get_secret_key(password, salt)
    decoded = base64.b64decode(cipher_text)
    iv = decoded[:AES.block_size]
    cipher = AES.new(secret, AES.MODE_CBC, iv)
    original_bytes = unpad(cipher.decrypt(decoded[input_length:]))
    return bytes.decode(original_bytes)


f_salt = " "
secret_key = "password"
plain_text = "abishek bhatia is my name, what is your name? this is a message"

cipherText = encrypt(secret_key, f_salt, plain_text)
print("Cipher-Text: " + cipherText)

decryptedMessage = decrypt(secret_key, f_salt, cipherText)
print("Decrypted Message: " + decryptedMessage)