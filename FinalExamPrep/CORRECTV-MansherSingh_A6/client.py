'''
This is the client side implementation
'''

import socket
from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding

# Connect to the server
clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
IP = '127.0.0.1'
PORT = 65432
clientsocket.connect((IP, PORT))

# Receive the welcome message from the server
welcomeMsg = clientsocket.recv(1024).decode()
print(welcomeMsg)

# Send a message to the server
clientsocket.send("Hello".encode())

# Receive the certificate from the server
cert_data = b""
while True:
    chunk = clientsocket.recv(1024)
    if not chunk:
        break
    cert_data += chunk

# Load the certificate from the received data
cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)

# Convert the certificate to a cryptography.x509.Certificate object
cert_cryptography = x509.load_pem_x509_certificate(cert_data, default_backend())

# Get the public key from the certificate
pubkey = cert_cryptography.public_key()

# Verify the certificate using the public key
try:
    pubkey.verify(
        cert_cryptography.signature,
        cert_cryptography.tbs_certificate_bytes,
        padding.PKCS1v15(),  # Using PKCS1v15 padding
        cert_cryptography.signature_hash_algorithm
    )
    print("Certificate verification successful.")
except Exception as e:
    print("Certificate verification failed:", e)

# Now we need to create a new key using AES and encrypt it using the public key
# Generate a random AES key

# Use a Keygen function from openSSL
AES_key = crypto.PKey()
AES_key.generate_key(crypto.TYPE_RSA, 2048)

# Encrypt the AES key using the public key
encrypted_AES_key = pubkey.encrypt(
    AES_key.export_key(),  # The key to encrypt
    padding.PKCS1v15()  # Using PKCS1v15 padding
)

# Send the encrypted AES key to the server
clientsocket.send(encrypted_AES_key)


# Close the connection
clientsocket.close()
