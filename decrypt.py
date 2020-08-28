import base64
import os
import getpass
import settings
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

FOLDER_NAME = settings.FOLDER_NAME

password = getpass.getpass("Password:")

#generate and save salt
saltFile = open("salt.txt", "r")
salt = saltFile.read()
saltFile.close()

#generate the Fernet module
kdf = PBKDF2HMAC(
     algorithm=hashes.SHA256(),
     length=32,
     salt=salt,
     iterations=100000,
     backend=default_backend()
 )
keypass = base64.urlsafe_b64encode(kdf.derive(password))
fer = Fernet(keypass)

#retrieves Key file
keyFile = open("stuff.txt", "r")
encryptedKey = keyFile.read()
keyFile.close()
key = fer.decrypt(encryptedKey)
f = Fernet(key)

#Generate the file lists
mylist = os.listdir(FOLDER_NAME)
encryptedFileList = list(filter(lambda item: item.find("encrypted") != -1, mylist))
unencryptedList = list(filter(lambda item: item.find("encrypted") == -1, mylist))

for filename in encryptedFileList:
	encryptedTestFile = open(FOLDER_NAME + "/" + filename, "r")
	decryptedFilename = filename.replace("encrypted", "")
	testFile = open(FOLDER_NAME + "/" + decryptedFilename, "w+")
	encryptedText = encryptedTestFile.read()
	decryptedText = f.decrypt(encryptedText)
	testFile.write(decryptedText)

	encryptedTestFile.close()
	testFile.close()
