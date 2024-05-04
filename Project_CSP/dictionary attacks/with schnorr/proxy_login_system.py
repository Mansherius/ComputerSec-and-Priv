import hashlib
import socket
import sqlite3
import schnorr_2 as schnorr
import rsa


class LoginSystem:
    def __init__(self, server_address='127.0.0.1', port=65432, db_file="user_authentication.db"):
        self.input_length = 16 # AES block size, 128 bits
        self.iter_count = 65536 # number of iterations
        self.key_len = 32 
        self.server_address = server_address
        self.port = port
        self.db_file = db_file
        self.conn = sqlite3.connect(self.db_file)
        self.c = self.conn.cursor()
        self.check_db()
    
    def check_db(self):
        self.c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
        if self.c.fetchone() is None:
            self.c.execute('''
                CREATE TABLE users (
                    username TEXT PRIMARY KEY,
                    password TEXT NOT NULL
                );
            ''')
            print(f"New table 'users' created in {self.db_file}")
        else:
            print(f"Table 'users' already exists in {self.db_file}")

    def signup(self, email, pwd):
        
        enc = pwd.encode()
        hash1 = hashlib.md5(enc).hexdigest()
        # check if user already exists in the database
        self.c.execute("SELECT username FROM users WHERE username = ?", (email,))
        if self.c.fetchone() is not None:
            print("User already exists!")
            return None
        self.c.execute("INSERT INTO users VALUES (?, ?)", (email, hash1))
        self.conn.commit()
        print(f"New credentials stored for email: {email}")
        self.c.execute("SELECT * FROM users")
        print(self.c.fetchall())
        print("You have registered successfully!")
        return None

    def login(self, email, pwd):
        pwd= pwd.lower()
        self.c.execute("SELECT password FROM users WHERE username = ?", (email,))
        row = self.c.fetchone()
        print("Original Password:",row[0])
        if row is not None:
            if pwd == row[0]:
                print("Login Successful!")
                return email
            else:
                return None
        return None

    
    def run(self, user, pwd):
        '''with open("server_public_key.pem", "rb") as key_file:
            public_key_data = key_file.read()
        # format the key data as a public key
        public_key_server = rsa.PublicKey.load_pkcs1(public_key_data)'''
        user = self.login(user, pwd)
        if user is None:
            return 0
        else:
            print("Login Done. Moving on to other stuff now.")
            while True:
                # ask user if they wanna go forward with the server access
                print("Do you want to access the server?")
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.connect((self.server_address, self.port))
                ch = input("Enter 1 for yes and 0 for no: ")
                if ch=="0":
                    client.send("exit".encode())
                    return None
                elif ch=="1":
                    print(f"Connection established with {self.server_address}")
                    client.send("hello".encode())
                    print("Hello sent to server!")
                    resp= client.recv(1024).decode()
                    if resp == "hello":
                        publicKey, alpha = schnorr.keygen()
                        # convert publicKey into a list
                        p, g, h = int(publicKey[1]), int(publicKey[0]), int(publicKey[2])
                        alpha= int(alpha)
                        message = ''.join(format(ord(i), '08b') for i in user)
                        signatureC, signatureZ = schnorr.sign(message, alpha, p, g, h)
                        # Send the signature to the server along with the username and the public key
                        client.send(f"{message}\n{signatureC}\n{signatureZ}".encode())
                        r= client.recv(1024).decode()
                        if r == "True":
                            print("Server has verified the signature")
                            print("Access granted!")
                            return 1
                        elif r == "False":
                            print("Server has not verified the signature. Access denied!")
                            return "done"
