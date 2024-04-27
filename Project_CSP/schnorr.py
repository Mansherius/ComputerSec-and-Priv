import hashlib
import random
from Crypto.Util import number

def genPrime(bitsize=128):
    prime = number.getPrime(bitsize)
    return prime

def genG(p):
    q = random.randint(2, p - 1)
    while number.GCD(q, p) != 1:
        q = random.randint(2, p - 1)
    return q

def createH(p, g):
    alpha = random.randint(1, p - 1)
    h = pow(g, alpha, p)
    return h, alpha

def keygen():
    p = genPrime()
    g = genG(p)          
    h, alpha = createH(p, g)

    def H(message):
        return int(hashlib.sha256(message.encode()).hexdigest(), 16) % p
    
    public_key = {'g': g, 'G': p, 'h': h, 'H': H}
    private_key = alpha

    return public_key, private_key

def sign(message, secret_key, public_key):
    beta = random.randint(1, public_key['G'])
    y = pow(public_key['g'], beta, public_key['G'])
    c = public_key['H'](str(y) + message)
    z = (beta + secret_key * c) % public_key['G']
    return (c, z)

def verify(signature, public_key, message):
    c, z = signature
    g = public_key['g']
    h = public_key['h']
    m_hash = public_key['H'](str(pow(g, z, public_key['G'])) + message)
    return c == m_hash

# Example usage
public_key, private_key = keygen()
message = "Hello, world!"
signature = sign(message, private_key, public_key)
verification = verify(signature, public_key, message)
print("Signature Verification Result:", verification)
