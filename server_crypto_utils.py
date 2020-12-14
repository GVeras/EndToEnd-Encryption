import hashlib
import uuid

def accounts_file_exists():
    try:
        allUsers = open("accounts.txt","r")
        return True
    except:
        allUsers = open("accounts.txt","w")
        allUsers.close()
        return False

def user_exists(user):
    userExist = False
    if accounts_file_exists:
        return userExist
    allUsers = open("accounts.txt","r")
    for line in allUsers:
        line = line.strip("\n")
        currentUser, hashed_pass, role = line.split(",")
        if currentUser == user:
            userExist = True
            break
    allUsers.close()
    return userExist

def hash_pass(password):
    # uuid is a random id generator, it will be used to generate the salt
    # the salt will be a 32 character hexadecimal string
    salt = uuid.uuid4().hex
    salted_pass = salt + password

    # Use hashlib sha512 algorithm to hash the password and salt together
    return hashlib.sha512(salted_pass.encode()).hexdigest() + '---' + salt

def valid_login(user, password):
    if not accounts_file_exists:
        return False
    
    userExists = False
    allUsers = open("accounts.txt","r")
    for line in allUsers:
        line = line.strip("\n")
        currentUser, hashed_pass, role = line.split(",")
        if currentUser == user:
            userExists = True
            break

    if userExists == False:
        return False
    
    info = hashed_pass.split("---")
    hashed_pass = info[0]
    salt = info[1]
    salted_pass = (salt + password).encode()

    if hashlib.sha512(salted_pass).hexdigest() == hashed_pass:
        return True
    return False

