import rsa
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import socket

input_length = 16 # AES block size, 128 bits
iter_count = 65536 # number of iterations
key_len = 32 
# The IP Address of the server. We will be using localhost IP Address as the socket's IP Address.
server_address= '127.0.0.1' 
# The port we will be using for the socket.
port = 5000 


def signup(public_key,client):
    email = input("Enter email address:")
    pwd = input("Enter password: ")
    conf_pwd = input("Confirm password: ")
    if conf_pwd == pwd:
        # check if pwd is secure
        if len(pwd) < 8:
            print("Password should be atleast 8 characters long!")
            return
        enc = conf_pwd.encode()
        hash1 = hashlib.md5(enc).hexdigest()
        credentials = f"{email}\n{hash1}"
        encrypted_credentials = rsa.encrypt(credentials.encode(), public_key)
        # Send 'encrypted_credentials' to the server
        client.send(("signup\n".encode()+encrypted_credentials))
        print("You have registered successfully!")
    else:
        print("Password is not same as above! \n")

def login(public_key,client):
    email = str(input("Enter email: "))
    pwd = str(input("Enter password: "))
    auth = pwd.encode()
    auth_hash = hashlib.md5(auth).hexdigest()
    credentials = f"{email}\n{auth_hash}"
    encrypted_credentials = rsa.encrypt(credentials.encode(), public_key)
    # Send 'encrypted_credentials' to the server
    client.send(("login\n".encode()+encrypted_credentials))
    # The server will respond whether the login was successful or not
    response = client.recv(1024).decode()
    if response == "1":
        print("Login Successful!")
    else:
        print("Login Failed!")
# Assume 'public_key' is the public key received from the server
with open("server_public_key.pem", "rb") as key_file:
    public_key_data = key_file.read()
# format the key data as a public key
public_key = rsa.PublicKey.load_pkcs1(public_key_data)

while 1:
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((server_address, port))
    print("********** Login System **********")
    print("1.Signup")
    print("2.Login")
    print("3.Exit")
    ch = int(input("Enter your choice: "))
    if ch == 1:
        signup(public_key,client)
    elif ch == 2:
        login(public_key,client)
    elif ch == 3:
        break
    else:
        print("Wrong Choice!")
