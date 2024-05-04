'''
This is the server side of the implementation
'''

import socket
from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
# Now we need to open the socket 
serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# The above two lines of code create a socket object and set the socket options
# The first argument is the address family, the second argument is the socket type
# The setsockopt() method is used to set the options for the socket

# Now we need to bind the socket to the address
host = '127.0.0.1'  # Localhost: This is a loopback address so that both the programs can run on the same machine
PORT = 65432    # Port to listen on (non-privileged ports are > 1023), It is above 5000 to ensure that the port is not previously being used

serversocket.bind((host, PORT))   # The bind() method binds the socket to the address

# Now we need to listen for connections tell the user that the server has started
print("The server is up and running!")

def server():
    while True: # The server will keep running until the client sends a message to stop
        (clientsocket, address) = serversocket.accept() 
        print(f"Connection from {address} has been established!")
        newClient(clientsocket)
        return address
    
def newClient(clientsocket):
    # First we send the welcome message to the client
    welcomeMsg = "Welcome to the server!"
    clientsocket.send(welcomeMsg.encode())

    helloMsg = clientsocket.recv(1024).decode()
    print(f"{helloMsg} from the client")

    # We will use openssl on terminal to do the generation and store the keys in the same folder as this so that we can 
    # use them in the code

    # Loading the RSA and DSA keys from the files
    with open("privkeyRSA2048.pem", "r") as file:
        privkeyS_RSA = crypto.load_privatekey(crypto.FILETYPE_PEM, file.read())
    with open("pubkeyRSA2048.pem", "r") as file:
        pubkeyS_RSA = crypto.load_publickey(crypto.FILETYPE_PEM, file.read())

    with open("privkeyDSA1024.pem", "r") as file:
        privkeyS_DSA = crypto.load_privatekey(crypto.FILETYPE_PEM, file.read())
    with open("pubkeyDSA1024.pem", "r") as file:
        pubkeyS_DSA = crypto.load_publickey(crypto.FILETYPE_PEM, file.read())

    # Now we have to compute the certificate
    # The certificate will be signed using the private key of the server (DSA)
    # The certificate will contain the public key of the server (RSA)
    # The certificate subject will be the email id 

    # Let us create the certificate using openssl

    # Now we load that certificate and send it to the client
    with open("cert.pem", "r") as file:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, file.read())

    cert_json = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode()
    clientsocket.send(cert_json.encode())

    # Recieve the encrypted AES key from the client
    encrypted_AES_key = b""
    while True:
        chunk = clientsocket.recv(1024)
        if not chunk:
            break
        encrypted_AES_key += chunk

    # Decrypt the AES key using the private key of the server (RSA) that we have above
    AES_key = privkeyS_RSA.decrypt(encrypted_AES_key, padding.PKCS1v15())

    # Check the decrypted AES key
    print(f"The decrypted AES key is: {AES_key}")



# Now we create a loop to ensure that the server is always up and listening for connections
while True:
    serversocket.listen(4)
    print("The server is listening for connections")
    address = server()

    # Once this is closed, We know that the client is disconnected and we can start listening for another connection
    print(f"The client has disconnected from address {address}")