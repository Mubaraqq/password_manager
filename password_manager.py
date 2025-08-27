from cryptography.fernet import Fernet, InvalidToken  # tools for encryption/decryption and handling bad keys.
import hashlib   # creates cryptographic hashes (SHA-256) of passwords
import base64  # encodes data for safe storage
import os  

# generate and save a key (do this once)
def write_key(master_pwd: str):
    # takes master password hashes it with SHA-256, and encodes to base64
    # fernet requires base64 32-byte key
    hash_pwd = hashlib.sha256(master_pwd.encode()).digest()
    key = base64.urlsafe_b64encode(hash_pwd)
    # saves the key to key.key.
    with open('key.key', 'wb') as file_key:
        file_key.write(key)
    
    # also store a test value encrypted with this key
    # encrypts the text "validation_test" and saves it to validation.key to verify passwords later
    fer = Fernet(key)
    test_value = fer.encrypt(b"validation_test")
    with open('validation.key', 'wb') as val_file:
        val_file.write(test_value)


# load key using the same master password and validate it 
def load_and_validate_key(master_pwd: str):
        # loads and verifies key. if the password is wrong, fernet won't decrypt correctly.
        try:
            # Recreates the key from the entered master password
            hash_pwd = hashlib.sha256(master_pwd.encode()).digest()
            key = base64.urlsafe_b64encode(hash_pwd)
            fer = Fernet(key)

            # decrypt the validation.key file
            with open('validation.key', 'rb') as val_file:
                encryted_test = val_file.read()
            decrypted_test = fer.decrypt(encryted_test)

            # if decrypted text matches "validation_test", returns the fer object
            if decrypted_test != b"validation_test":
                raise InvalidToken('Validation failed!')
            
            return fer   # return the fernet object if validation succeeds
        
        except Exception:
            print('Invalid master password: Access Denied!')
            exit(1)


master_pwd = input('What is your master password? ')

'''
    uncomment write_key(master_pwd) and run the program once with your desired master password.
    comment it out again for normal use.
'''
# first time? uncomment the write_key function call below to set the master key:
#write_key(master_pwd)
#print("Master password set up successfully!")

# load and validate the key
# gets the fer object only if password is correct
# exits if password is wrong

try:
    fer = load_and_validate_key(master_pwd) 
except:
    exit(1)

# gets account name and password from user
# encrypts the password using the validated fer object
def add():
    name = input('Accont name: ')
    pwd = input('Password: ')

    with open('password.txt', 'a') as f:
        f.write(name + " | " + fer.encrypt(pwd.encode()).decode() + "\n")

# reads all lines from password.txt if file is empty, shows message
def view():
    try:
        with open('password.txt', 'r') as f:
            lines = f.readlines()
            if not lines:
                print("You don't have any passwords stored yet.")
                return
            
            for line in lines:
                data = line.rstrip()
                user, passw = data.split("|")
                decrypted_pwd = fer.decrypt(passw.strip().encode()).decode()
                print(f'User:{user} | Password:{decrypted_pwd}')
    except FileNotFoundError:
        print("You don't have any passwords stored yet.")
    except Exception:
                print("Wrong master password! Cannot decrypt stored passwords.")


# continuous menu: asks user to add, view, or quit
while True:
    mode = input('would you like to add a new password or view existing ones (add/view), press q to quit? ').lower()

    if mode == 'q':
        break

    if mode == 'add':
        add()
    elif mode == 'view':
        view()
    else:
        print('Invalid option. Try again please.')
        continue

