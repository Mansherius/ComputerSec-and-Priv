import random
import sys
from Crypto.Util import number
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def genPrime(bitsize=128):
    prime = number.getPrime(bitsize)
    return prime

def genG(p):
    # Generate a random number smaller than p
    q = random.randint(2, p - 1)
    # Check if q and p are coprime
    while number.GCD(q, p) != 1:
        q = random.randint(2, p - 1)
    return q

def createH(p, g):
    # We have to choose alpha uniformly from {1, . . . , p-1}
    alpha = random.randint(1, p - 1)
    # Calculate g^alpha mod p
    h = pow(g, alpha, p)
    return h, alpha

def keyGen(h2, alpha, p):
    # Calculate h2^alpha mod p efficiently using modular exponentiation
    return pow(h2, alpha, p)

# AES functions

hash = "SHA256"
inputLen = 16
countIter = 65536
keyLen = 32

def pad(s):
    lenofPad = inputLen - len(s) % inputLen
    padStr = chr(lenofPad)
    paddedInput = s + padStr * lenofPad
    return paddedInput

def unpad(s):
    unpaddedInput = s[0:-ord(s[-1:])]
    return unpaddedInput

def getSKey(password, salt):
    pw = password.encode()
    salt = salt.encode()
    secretKey = hashlib.pbkdf2_hmac(hash, pw, salt, countIter, keyLen)
    return secretKey

def encrypt(password, salt, message):
    secret = getSKey(password, salt)
    message = pad(message)
    iv = get_random_bytes(inputLen)
    cipher = AES.new(secret, AES.MODE_CBC, iv)
    cipherBytes = base64.b64encode(iv + cipher.encrypt(message.encode("utf8")))
    return cipherBytes.decode()

def decrypt(password, salt, textCipher):
    secret = getSKey(password, salt)
    decoded = base64.b64decode(textCipher)
    iv = decoded[:AES.block_size]
    cipher = AES.new(secret, AES.MODE_CBC, iv)
    ogBytes = unpad(cipher.decrypt(decoded[inputLen:]))
    return ogBytes.decode()

# Test the updated functions
fSalt = " "
secretKey = "password"
plainText = "abishek bhatia is my name, what is your name? this is a message"

cipherText = encrypt(secretKey, fSalt, plainText)
print("Cipher-Text: " + cipherText)

decryptedMessage = decrypt(secretKey, fSalt, cipherText)
print("Decrypted Message: " + decryptedMessage)
