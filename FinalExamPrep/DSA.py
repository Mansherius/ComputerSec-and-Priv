'''
I will be using openSSL to generate RSA public and private keys, practice certificate generation and authentication, as well as digital signatures, DSA and RSA
'''


from OpenSSL import crypto, SSL

# Generate an RSA keypair (pk_P, sk_p) for a user P

def generate_RSA_keypair():
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 1024)
    return key

# Generate a certificate for a user P signed by a CA

def generate_certificate(key, ca_key, ca_cert):
    cert = crypto.X509()
    cert.get_subject().C = "US" #email id of
    cert.get_subject().ST = "California"
    cert.get_subject().L = "San Francisco"
    cert.get_subject().O = "Google"
    cert.get_subject().OU = "IT"
    cert.get_subject().CN = "P"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(31536000)
    cert.set_issuer(ca_cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(ca_key, 'sha1')
    return cert

# Generate a DSA keypair (pk_Y, sk_Y) for a user Y

def generate_DSA_keypair():
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_DSA, 1024)
    return key

