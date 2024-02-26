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

We are not allowed to use the random modle in python, so we will use the following method to generate a random number:
    - We will base our algorithm on the following theorem:
        - A continuous Random variable (X, fx) is said to be uniform on the interval [a,b] if its probability density function is given by:
            fx = 0 for x < a
            fx = 1/(b-a) for a <= x <= b
            fx = 0 for x > b


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