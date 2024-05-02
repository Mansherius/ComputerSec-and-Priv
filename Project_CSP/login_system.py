import hashlib
import socket
import sqlite3

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
        self.c.execute("INSERT INTO users VALUES (?, ?)", (email, hash1))
        self.conn.commit()
        print(f"New credentials stored for email: {email}")
        self.c.execute("SELECT * FROM users")
        print(self.c.fetchall())
        print("You have registered successfully!")


    def login(self, email, pwd):
        auth = pwd.encode()
        hash2 = hashlib.md5(auth).hexdigest()
        self.c.execute("SELECT password FROM users WHERE email = ?", (email,))
        row = self.c.fetchone()
        if row is not None:
            if hash2 == row[0]:
                print("Login Successful! Access granted to Server!")
                return email, pwd
            else:
                return None, None
        else:
            print("User not found!")
            return None, None

    def run(self, ch, user, pwd):
        if ch == 1:
            self.signup(user, pwd)
        elif ch == 2:
            user, pwd = self.login(user, pwd)
            if user is None:
                return 0
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((self.server_address, self.port))
            print(f"Connection established with {self.server_address}")
            return 1
        elif ch == 3:
            print("Exiting...")
            exit()
        else:
            print("Wrong Choice!")
