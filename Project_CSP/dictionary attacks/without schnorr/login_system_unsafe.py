import hashlib
import socket
import sqlite3
import rsa

class LoginSystem:
    def __init__(self, server_address='127.0.0.1', port=5000, db_file='authent.db'):
        self.input_length = 16 # AES block size, 128 bits
        self.iter_count = 65536 # number of iterations
        self.key_len = 32 
        self.server_address = server_address
        self.port = port
        self.db_file = db_file
        self.conn = sqlite3.connect(self.db_file)
        self.c = self.conn.cursor()
        self.check_db()
        # generate private and public keys and write the public key onto a file
        (self.public_key_client, self.private_key_client) = rsa.newkeys(2048)
        with open("client_public_key.pem", "wb") as key_file:
            key_file.write(self.public_key_client.save_pkcs1())

    def check_db(self):
        self.c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
        if self.c.fetchone() is None:
            self.c.execute('''
                CREATE TABLE users (
                    email TEXT PRIMARY KEY,
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
        self.c.execute("SELECT email FROM users WHERE email = ?", (email,))
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

    def login_stuff(self, user):
        if user is None:
            return 0
        else:
            with open("server_public_key.pem", "rb") as key_file:
                public_key_data = key_file.read()
            # format the key data as a public key
            public_key_server = rsa.PublicKey.load_pkcs1(public_key_data)
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((self.server_address, self.port))
            print(f"Connection established with {self.server_address}")
            client.send("hello".encode())
            print("Hello sent to server!")
            data = client.recv(1024).decode()
            if data =="hello":
                print("Hello received from server!")
                print("1. Add new site")
                print("2. Retrieve password")
                print("3. Exit")
                ch = int(input("Enter choice: "))
                if ch == 1:
                    name = input("Enter username to add: ")
                    site_name = input("Enter the site name: ")
                    password = input("Enter the password: ")
                    action= 'add'
                    credentials = f"{action},{user}\n{site_name}\n{password}\n{name}"
                    encrypted_credentials = rsa.encrypt(credentials.encode(), public_key_server)
                    client.send(encrypted_credentials)
                    response = client.recv(1024).decode()
                    client.close()
                    if response == "1":
                        print("Site added successfully!")
                    elif response == "2":
                        print("Site already exists!")
                    else:
                        print("Failed to add site!")
                elif ch == 2:
                    site_name = input("Enter the site name to retrieve password: ")
                    action= 'retrieve'
                    credentials = f"{action},{user}\n{site_name}"
                    encrypted_credentials = rsa.encrypt(credentials.encode(), public_key_server)
                    client.send(encrypted_credentials)
                    response = client.recv(1024)
                    response = rsa.decrypt(response, self.private_key_client).decode()
                    client.close()
                    if response == "Password not found.":
                        print(response)
                    else:
                        print(f"Password for {site_name}: {response}")
                elif ch == 3:
                    print("Exiting...")
                    exit()
                else:
                    print("Wrong Choice!")

    def login(self, email, pwd):
        pwd= pwd.lower()
        auth = pwd.encode()
        hash2 = hashlib.md5(auth).hexdigest()
        self.c.execute("SELECT password FROM users WHERE email = ?", (email,))
        row = self.c.fetchone()
        if row is not None:
            if hash2 == row[0]:
                print("Login Successful! Access granted to Server!")
                return email, pwd
        return None

    def run(self, ch, user, pwd):
        if ch == 1:
            self.signup(user, pwd)
        elif ch == 2:
            userpass = self.login(user, pwd)
            if userpass is None:
                return 0
            else:
                user= userpass[0]
                print("Login Done. Moving on to other stuff now.")
                self.login_stuff(user)
            return 1
        elif ch == 3:
            print("Exiting...")
            exit()
        else:
            print("Wrong Choice!")
