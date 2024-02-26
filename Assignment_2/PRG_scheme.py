'''
This code is an encryption and decryption scheme using the PRG scheme.

Building blocks of the scheme:
A PRG G: {0,1}^80 -> {0,1}^160

Maybe one of the candidate PRG's from the lecture notes - 

We shall use the subset sum PRG - 
   - q is a positive integer and Z_q is the set of integers {0, q-1}
   - We then choose n random integers in Z_q and let m = [log2 q]
   - for s = s0, s1 ... s(n-1) in {0,1}^n, 
   - G: {0,1}^n -> {0,1}^m
    - G(s) = sum(s[i]*a[i] for i in range(n)) mod q


Now we must also design a code that can be used to select uniformly random elements from the set {0,1}^80. (the Key space)

We are not allowed to use the random modle in python for choosing discrete values, so we will use one of the following methods to generate a random number:
    - We will base our algorithm on the following theorem:
        - A continuous Random variable (X, fx) is said to be uniform on the interval [a,b] if its probability density function is given by:
            fx = 0 for x < a
            fx = 1/(b-a) for a <= x <= b
            fx = 0 for x > b
    - We can also use a Bernoulli Distribution to sample a random number from the key space
        - A Bernoulli distribution is a discrete probability distribution for a random variable which takes the value 1 with probability p and the value 0 with probability 1-p
        - We can use the Bernoulli distribution to sample a random number from the key space by setting p = 0.5


Now let us discuss the encryption and decryption scheme:

We will take a message m that is at most 80 bits long (can be either a text or a text file)
Then we use appropriate encoding to convert the message into a unique m in {0,1}^80
The encryption algorithm will take the message m and the key k and produce a ciphertext c.
Encryption algorithm:
    pick r from {0,1}^80 uniformly at random
    z = G(k XOR r) XOR m
    output the ciphertext c = (r, z)

    We can choose an appropriate encoding for representing the ciphetext as a file


The Decryption algorithm will take the ciphertext file and the key k
Decryption algorithm:
    read the ciphertext c = (r, z)
    m = G(k XOR r) XOR z
    decode m into its text representation and then output the message

    We can choose an appropriate encoding for representing the message as a file 
'''

# Code for keygen
# The Key space is set to K = {0,1}^80
# The keygen algorithm samples a random key from the key space.
# We must write an algorithm that samples uniformly at random from this key space
# We can use a Bernoulli distribution to sample a random number from the key space

'''
Ensure that message.txt is stored in the same directory as this file
All the other files will also be written to this directory
'''

import random

def keygen():
    key_length = 80

    # Generate an 80-bit binary string using random.random()
    # We can use the Bernoulli distribution to sample a random number from the key space by setting p = 0.5
    # Now as the key space is simply {0,1}^80, we can simply assign 0's and 1's based on the value of random.random()

    key = ''.join('1' if random.random() < 0.5 else '0' for _ in range(key_length))

    return key

key = keygen()
# Save the key to a file
with open('key.txt', 'w') as file:
    file.write(key)

# Now we create the PRG
# We will use the subset sum PRG
# The PRG G: {0,1}^80 -> {0,1}^160
# We will choose q = 2^160
# We will choose n = 80 (according to the Key length)
        
q = 2**160
n = 80
a = [random.randint(0, q - 1) for _ in range(n)]

def PRG(s):  # Takes in one input (key XOR r)

    # Now we calculate the sum
    output = sum(int(s[i]) * a[i] for i in range(n)) % q

    # print("Output:", output)

    # Now we convert the output to a binary string that is 160 bits long
    output = bin(output)[2:]

    # If the output is less than 160 bits, we pad it with 0's
    output = '0' * (160 - len(output)) + output

    # print("Binary Output:", output)
    # print("length of output:", len(output))

    return output


# Now we write the encryption algorithm
# This encryption algorithm will take the key XOR r as input for the PRG and XOR that with the message
# The encryption algorithm takes the message file and the key file as inputs

def encrypt(message_file, key_file):
    # Read the message file
    with open(message_file, 'r') as file:
        message = file.read()

    # print("Message opened successfully!")

    # Read the key file
    with open(key_file, 'r') as file:
        key = file.read()
    
    # print("Key opened successfully!")

    # Convert the message into a binary string in chunks of 8 bits
    message_binary = ''.join(format(ord(i), '08b') for i in message)

    # If the message is less than 160 bits, pad it with 0's
    message_binary = message_binary + '0' * (160 - len(message_binary))

    # Check if the message is at most 160 bits long
    if len(message_binary) > 160:
        raise ValueError('The message is too long')
    
    # print("Message in binary is: ", message_binary)
    # print("Length of message:", len(message_binary))

    # Generate r from {0,1}^80 uniformly at random
    r = keygen()

    # Now we calculate z = G(k XOR r) XOR m
    s = ''.join('1' if key[i] != r[i] else '0' for i in range(80))  # k XOR r
    # print("s is: ", s)
    w = PRG(s)  # G(k XOR r)

    # print("w is: ", w)

    # Now we process the binary message in chunks of 8 bits
    z = ''.join('1' if w[i] != message_binary[i] else '0' for i in range(len(w)))

    # Save the ciphertext to a file
    with open('ciphertext.txt', 'w') as file:
        file.write(r + '\n' + z)
# Now we write the decryption algorithm
# This decryption algorithm will take the ciphertext file and the key file as inputs

def decrypt(ciphertext_file, key_file):
    # Read the ciphertext file
    with open(ciphertext_file, 'r') as file:
        ciphertext = file.read().split('\n')

    r = ciphertext[0]
    z = ciphertext[1]

    # Read the key file
    with open(key_file, 'r') as file:
        key = file.read()

    # Now we calculate m = G(k XOR r) XOR z
    s = ''.join('1' if key[i] != r[i] else '0' for i in range(80))  # k XOR r
    w = PRG(s)  # G(k XOR r)

    # Process the binary message in chunks of 8 bits
    m_binary = ''.join('1' if w[i] != z[i] else '0' for i in range(len(w)))

    # Pad the binary message with zeros to make its length a multiple of 8
    m_binary = m_binary.ljust((len(m_binary) + 7) // 8 * 8, '0')

    # Convert the binary representation to ASCII characters
    m_text = ''.join(chr(int(m_binary[i:i+8], 2)) for i in range(0, len(m_binary), 8)if m_binary[i:i+8] != '00000000')

    # Save the decrypted message to a file
    with open('decrypted_message.txt', 'w') as file:
        file.write(m_text)

# Now we test the encryption and decryption algorithms
encrypt('message.txt', 'key.txt')
decrypt('ciphertext.txt', 'key.txt')