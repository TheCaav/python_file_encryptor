import base64
import os
import getpass
from settings import FOLDER_NAME
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

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

#encrypt Files and delete old ones
for filename in unencryptedList:
	testFile = open(FOLDER_NAME + "/" + filename, "r")
	testFileText = testFile.read()

	encryptedFileText = f.encrypt(testFileText)

	encryptedTestFile = open(FOLDER_NAME + "/encrypted" + filename, "w+")
	encryptedTestFile.write(encryptedFileText)
	testFile.close()
	encryptedTestFile.close()
	os.remove(FOLDER_NAME + "/" + filename)

