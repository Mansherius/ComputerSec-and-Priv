# This is the client side code and is how we will interact with the server
'''
All print statements that are not required but were created as checks have been commented out
'''
import socket
import defs     # Importing the defs.py file to use the functions defined in it

# Now we need to open the socket
clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
IP = '127.0.0.1'
PORT = 65432

clientsocket.connect((IP, PORT))

# First we receive the welcome message from the server
welcomeMsg = clientsocket.recv(1024).decode()
print(welcomeMsg)

# Now we will run the first part of the assignment code
clientsocket.send("Hello".encode())

# We receive the values in a string format 
# values = f"{p}, {g}, {h1}"
values = clientsocket.recv(1024).decode()
    
# Now we need to split the values into p, g and h1
values = values.split(", ")
p = int(values[0])
# print(f"p is - {p}")
g = int(values[1])
# print(f"g is - {g}")
h1 = int(values[2])
# print(f"h1 is - {h1}")

# Now we need to calculate h2 and beta
h2, beta = defs.createH(p, g)
# print(f"h2 is - {h2}")

# Now we need to send the value of h2 to the server
clientsocket.send(str(h2).encode())

# Now we compute the key using the Keygen function
key = defs.keyGen(h1, beta, p)
# print(f"Key is -{key}")

# Now we have verified that all the keys and everything else are being created, 
# we can now send the message to the server
fSalt = " "
msg = "Hi my name is Mansher. This is test one of the encryption"
cipherText = defs.encrypt(str(key), fSalt, msg)
# print(f"Cipher Text is - {cipherText}")

# Now we send the cipher text to the server
clientsocket.send(cipherText.encode())

# Now we recieve the decrypted message from the server and check 
# if it is the same as the original message
msg2 = clientsocket.recv(1024).decode()
# print(f"Message 2 is - {msg2}")

# Now we check if the message is the same as the original message
checker = defs.checkMsg(msg, msg2)

clientsocket.close()