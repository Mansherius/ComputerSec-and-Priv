import hashlib
import random
from Crypto.Util import number

def genPrime(bitsize=128):
    prime = number.getPrime(bitsize)
    return prime

def genG(p):
    q = random.randint(2, p - 1)
    return q

def createH(p, g):
    alpha = number.getRandomRange(1, p - 1)
    h = pow(g, alpha, p)
    return h, alpha

def H(r, message):
    hash = hashlib.sha256()
    hash.update(str(r).encode())
    hash.update(message.encode())
    return int(hash.hexdigest(), 16)

def keygen():
    p = genPrime()
    g = genG(p)          
    h, alpha = createH(p, g)
    public_key = [g, p, h]
    private_key = alpha
    return public_key, private_key

def sign(message, secret_key, p, g, h):
    beta = number.getRandomRange(1, p - 1)
    y = pow(g, beta, p)
    c = H(y, message) % p
    z = (beta + secret_key * c) % (p - 1)
    return c, z

def verify(c, z, p, g, h, message):
    j = (pow(g, z, p) * pow(pow(h, c, p),-1,p)) % p
    print(j)
    m_hash = H(j, message) % p
    print(m_hash, c)
    return m_hash == c


'''
# Example usage
public_key, private_key = keygen()
print("Public Key:", public_key)
p,g,h= public_key[1], public_key[0], public_key[2]
print("Private Key:", private_key)

message = "Hello, world!"

# Convert the message to binary
message = ''.join(format(ord(i), '08b') for i in message)

print("Message:", message)

signatureC, signatureZ = sign(message, private_key, p, g, h)
print("Signature:", signatureC, signatureZ)

verification = verify(signatureC, signatureZ, p, g, h, message)
print("Signature Verification Result:", verification)
'''
