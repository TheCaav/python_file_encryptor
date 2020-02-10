import base64
import os
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def createFolder(directory):
    try:
        if not os.path.exists(directory):
            os.makedirs(directory)
    except OSError:
        print ('Error: Creating directory. ' +  directory)

settings = open("settings.py", "w")
folderName = raw_input("Folder Name?")
createFolder(folderName)
settings.write("FOLDER_NAME = \"" + folderName + "\"")

#Check if password is typed right
hi = False
while hi == False:
	password = getpass.getpass("Password:")
	secondPassword = getpass.getpass("Password a second Time:")
	hi = password == secondPassword

#generate and save salt
salt = os.urandom(16)
salt_file = open("salt.txt", "w+")
salt_file.write(salt)
salt_file.close()

#generate the Fernet module
kdf = PBKDF2HMAC(
     algorithm=hashes.SHA256(),
     length=32,
     salt=salt,
     iterations=100000,
     backend=default_backend()
 )
passkey = base64.urlsafe_b64encode(kdf.derive(password))
f = Fernet(passkey)

key = Fernet.generate_key()
encryptedKey = f.encrypt(key)
keyFile = open("stuff.txt", "w+")
keyFile.write(encryptedKey)
keyFile.close()
