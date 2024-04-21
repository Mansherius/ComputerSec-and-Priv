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
# The IP Address of the server. We will be using localhost IP Address as the socket's IP Address.
server_address = '127.0.0.1'
# The port we will be using for the socket.
port = 65432
# creating private and public keys for the client
(public_key_client, private_key_client) = rsa.newkeys(2048)

# creating files for the public keys
with open("client_public_key.pem", "wb") as key_file:
    key_file.write(public_key_client.save_pkcs1())
with open("server_public_key.pem", "rb") as key_file:
    public_key_data = key_file.read()
# format the key data as a public key
public_key_server = rsa.PublicKey.load_pkcs1(public_key_data)

def signup(public_key,client):
    email = str(input("Enter email address:"))
    pwd = str(input("Enter password: "))
    conf_pwd = str(input("Confirm password: "))
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
        response = client.recv(1024).decode()
        if response == "0":
            print("Email already exists!")
        else:
            print("You have registered successfully!")
    else:
        print("Password is not same as above! \n")
def get_details(email,public_key,client):
    service= str(input("Enter service: "))
    # encrypt email and service into a string
    credentials = f"{email}\n{service}"
    encrypted_credentials = rsa.encrypt(credentials.encode(), public_key)
    # Send 'encrypted_credentials' to the server
    client.send(("get_details\n".encode()+encrypted_credentials))
    # The server will respond whether the login was successful or not
    response = client.recv(1024).decode()
    if response == "1":
        print("Details found!")
        # receive the encrypted details
        encrypted_details = client.recv(1024)
        # decrypt the details
        details = rsa.decrypt(encrypted_details, private_key_client)
        details = details.decode()
        print("Username: ",details.split('\n')[0], "Password: ",details.split('\n')[1])
    else:
        print("Details not found!")

def add_details(email,public_key,client):
    # take the email and password they want to add as input from the user along with the service
    user = str(input("Enter username: "))
    pword = str(input("Enter password: "))
    service = str(input("Enter service: "))
    # encrypt email, user, pword and service into a string
    credentials = f"{email}\n{user}\n{pword}\n{service}"
    encrypted_credentials = rsa.encrypt(credentials.encode(), public_key)
    # Send 'encrypted_credentials' to the server
    client.send(("adddetails\n".encode()+encrypted_credentials))
    # The server will respond whether the login was successful or not
    response = client.recv(1024).decode()
    if response == "1":
        print("Details added successfully!")
    elif response == "2":
        print("Details for service already exist,Do you want to update the details?")
        ch = str(input("Enter yes or no: "))
        if ch == "yes":
            # send this to the server
            client.send("yes".encode())
            response = client.recv(1024).decode()
            if response == "1":
                print("Details updated successfully!")
            else:
                print("Details not updated, please try again!")
    else:
        print("Details not added, please try again!")
    
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
        return 1,email
    else:
        print("Login Failed!")
        return 0,email


def exit(public_key,client):
    client.send("exit\n".encode()+rsa.encrypt("exit".encode(), public_key))
    client.close()


while 1:
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((server_address, port))
    print("********** Login System **********")
    print("1.Signup")
    print("2.Login")
    print("3.Exit")
    ch = int(input("Enter your choice: "))
    if ch == 1:
        signup(public_key_server,client)
    elif ch == 2:
        c,email= login(public_key_server,client)
        if c == 1:
        # Send "ready" message to indicate that client is ready for further instructions
            client.send("ready".encode())
            while 1:
                print("1.Add Details")
                print("2.Get Details")
                print("3.Exit")
                ch = int(input("Enter your choice: "))
                if ch == 1:
                    add_details(email,public_key_server,client)
                elif ch == 2:
                    get_details(email,public_key_server,client)
                elif ch == 3:
                    exit(public_key_server,client)
                    break
                else:
                    print("Wrong Choice!")
    elif ch == 3:
        exit(public_key_server,client)
        break
    else:
        print("Wrong Choice!")
