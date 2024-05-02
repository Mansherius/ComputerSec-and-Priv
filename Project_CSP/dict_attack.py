from login_system import LoginSystem

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
    p_list.extend([f"{i}123" for i in p_list])
    p_list.extend([f"{i}1234" for i in p_list])
    p_list.extend([f"{i}12345" for i in p_list])
    p_list.extend([f"123{i}" for i in p_list])
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
        # Read the dictionary file
        with open('names.txt', 'r') as file:
            passwords = file.read().splitlines()
        # create a file with all possible passwords
        f=make_user_pass_file(user)
        with open(f, 'r') as file:
            user_pw = file.read().splitlines()
        for i in passwords:
            r = login_system.run(ch, user, i)  # Pass the instance of LoginSystem as self
            if r:
                print(f"Password found in passwords: {i}")
                return None
            else:
                continue
        for i in user_pw:
            r = login_system.run(ch, user, i)
            if r:
                print(f"Password found in user_pwd: {i}")
                return None
            else:
                continue
    return None


if __name__ == "__main__":
    user= str(input("Enter username: "))
    pwd= str(input("Enter password: "))
    dictionary_attack(user, 1, pwd)
    dictionary_attack(user, 2)
