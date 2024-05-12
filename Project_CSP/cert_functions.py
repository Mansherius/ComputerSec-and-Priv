from OpenSSL import crypto
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes



##----------------- Client Side Functions -----------------##
# function to verify the certificate chain
def CertVerify(cert_chain):
    try:
        p_cert, y_cert = cert_chain[0], cert_chain[1] # p_cert is the parent certificate and y_cert is the child certificate

        # check if y-cert is self signed
        if y_cert.get_subject() == y_cert.get_issuer():
            print("Certificate is self signed!")
            # add the certificate to the certificate store
            store = crypto.X509Store()
            store.add_cert(y_cert)
        else:
            print("Certificate is not self signed!")
        # create a certificate store context
        store_ctx = crypto.X509StoreContext(store, p_cert)
        # verify the certificate chain
        store_ctx.verify_certificate()
        # clear the store
        store_ctx._store = None
        return 1  # Certificate chain is valid
    except Exception as e:
        print(f"Error: {e}")
        return 0  # Certificate chain is invalid
    
def extract_public_key(cert):
    return cert.get_pubkey()

def rsa_encrypt(message, public_key):
    # Encrypt the message using RSA public key, this method uses OAEP padding scheme with SHA256 as the hash function
    ciphertext = public_key.encrypt(
        message,# message to encrypt
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), # mask generation function
            algorithm=hashes.SHA256(), # hash function
            label=None # no label
        )
    )
    return ciphertext

##----------------- Server Side Functions -----------------##

def create_rsa_key(user):
    # generate RSA key pair
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    # store private key
    with open(f"{user}.key", "wb") as key_file:
        key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    
    # store public key
    with open(f"{user}.pub", "wb") as pub_file:
        pub_file.write(crypto.dump_publickey(crypto.FILETYPE_PEM, key))
    
    return key

def create_dsa_key(user):
    # generate DSA key pair
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_DSA, 1024)
    # store private key
    with open(f"{user}.key", "wb") as key_file:
        key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    # store public key
    with open(f"{user}.pub", "wb") as pub_file:
        pub_file.write(crypto.dump_publickey(crypto.FILETYPE_PEM, key))
    return key  

def create_certificate(
    public_key,
    issuer_private_key,
    emailAddress="emailAddress",
    commonName="commonName",
    CERT_FILE="selfsigned.crt",
    countryName="NT",
    localityName="Sonipat",
    stateOrProvinceName="Haryana",
    organizationName="CS2362/Spring2024",
    organizationUnitName="Ashoka University",
    issuer_cert= None,
    serialNumber=0,
    validityStartInSeconds=0,
    validityEndInSeconds=10*365*24*60*60):
    # create a cert
    cert = crypto.X509()
    cert.get_subject().C = countryName
    cert.get_subject().ST = stateOrProvinceName
    cert.get_subject().L = localityName
    cert.get_subject().O = organizationName
    cert.get_subject().OU = organizationUnitName
    cert.get_subject().CN = commonName
    cert.get_subject().emailAddress = emailAddress
    cert.set_serial_number(serialNumber)
    cert.gmtime_adj_notBefore(validityStartInSeconds)
    cert.gmtime_adj_notAfter(validityEndInSeconds)
    if issuer_cert:
        print("Issuer exists!")
        cert.set_issuer(issuer_cert.get_subject())
    else:
        print("Issuer does not exist!")
        cert.set_issuer(cert.get_subject())
    cert.set_pubkey(public_key)
    cert.sign(issuer_private_key, "sha256")
    with open(CERT_FILE, "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
    return cert

def rsa_decrypt(ciphertext, private_key):
    # Decrypt the ciphertext using RSA private key, this method uses OAEP padding scheme with SHA256 as the hash function
    plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
        )
    )
    return plaintext.decode()

def sign(message, sk):
    s= crypto.sign(sk, message.encode(), "sha256")
    return s

def send_cert(dsa_cert, client):
    cert= (crypto.dump_certificate(crypto.FILETYPE_PEM, dsa_cert).decode())
    print(cert)
    client.send(cert.encode())
    print("------CERTIFICATE SENT------")

def rsa_encrypt(message, public_key):
    # Encrypt the message using RSA public key, this method uses OAEP padding scheme with SHA256 as the hash function
    ciphertext = public_key.encrypt(
        message.encode(),# message to encrypt
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), # mask generation function
            algorithm=hashes.SHA256(), # hash function
            label=None # no label
        )
)
    return ciphertext

def rsa_decrypt(ciphertext, private_key):
    # Decrypt the ciphertext using RSA private key, this method uses OAEP padding scheme with SHA256 as the hash function
    plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
        )
    )
    return plaintext.decode()