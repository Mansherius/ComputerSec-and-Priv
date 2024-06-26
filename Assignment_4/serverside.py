import socket
import defs     # Importing the defs.py file to use the functions defined in it

'''
All print statements that are not required but were created as checks have been commented out
'''

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

    # Now we run the first part of the assignment code
    p = defs.genPrime(128)
    # print(f"p is - {p}")
    g = defs.genG(p)
    # print(f"g is - {g}")
    h1, alpha = defs.createH(p, g)
    # print(f"h1 is - {h1}")

    # Now we send the values of p, g and h1 to the client
    values = f"{p}, {g}, {h1}"
    clientsocket.send(values.encode())

    # Now we receive the value of h2 from the client
    h2 = int(clientsocket.recv(1024).decode())

    # print(f"h2 is - {h2}")
    # Now we calculate the key using the keyGen function
    key = defs.keyGen(h2, alpha, p)
    # print(f"Key is - {key}")

    # Now we receive the cipher text from the client
    cipherText = clientsocket.recv(1024).decode()
    # print(f"CipherText is - {cipherText}") # checks

    # Now we decrypt the cipher text
    fSalt = " "
    msg = defs.decrypt(str(key), fSalt, cipherText)
    # print(f"Decrypted message is - {msg}")

    # Now we send the decrypted message back to the client to check
    clientsocket.send(msg.encode())

# Now we create a loop to ensure that the server is always up and listening for connections
while True:
    serversocket.listen(4)
    print("The server is listening for connections")
    address = server()

    # Once this is closed, We know that the client is disconnected and we can start listening for another connection
    print(f"The client has disconnected from address {address}")