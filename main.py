# Batuhan KAYIM, Ozyegin University Computer Science
# 2018, CS 350 - Operating Systems Course Project

import getpass
import base64
import os
from os import stat
from pwd import getpwuid
from hashlib import md5
from base64 import b64decode
from base64 import b64encode
from Crypto import Random
from Crypto.Cipher import AES
import paramiko

# Padding for the input string --not
# related to encryption itself.
BLOCK_SIZE = 16  # Bytes
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                    chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


class AESCipher:
    """
    Usage:
        c = AESCipher('password').encrypt('message')
        m = AESCipher('password').decrypt(c)
    Tested under Python 3 and PyCrypto 2.6.1.
    """

    def __init__(self, key):
        self.key = md5(key.encode('utf8')).hexdigest()

    def encrypt(self, raw):
        raw = pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[16:])).decode('utf8', errors='ignore')


def find_owner(filename):
    return getpwuid(stat(filename).st_uid).pw_name


def get_items():
    files = sftp.listdir()
    file_list = []
    for f in files:
        if f[-4:] == ".dat":
            file_list.append(f[:-4])
    return file_list


def encrypt_file(file_path):
    try:
        if find_owner(file_path) == username:
            with open(file_path, "rb") as user_file:
                encoded_file = base64.b64encode(user_file.read())
            password = input("Password (will be used to decrypt the file later, better don't forget it): ")
            cipher = AESCipher(password).encrypt(encoded_file.decode("utf8"))
            file_name = file_path.split("/")[-1].split(".")[0]
            file_extension = file_path.split("/")[-1].split(".")[1]
            file_name = file_name + "." + file_extension
            upload_file(file_name=file_name, content=cipher)
            if file_name not in current_files:
                current_files.append(file_name)
            os.remove(file_path)
            print("\nYour file is uploaded to cloud and removed your local system")
        else:
            print("You aren't owner of the file. You cannot encrypt and store it")
    except Exception as e:
        print("Encrypt operation is failed")
        print(e)


def decrypt_file(file_name):
    try:
        if file_name in current_files:
            cipher = download_file(file_name + ".dat")
            password = input("Password to decrypt this file (password you used to store it): ")
            plain_data = AESCipher(password).decrypt(cipher)
            content = base64.b64decode(plain_data)
            create_file(file_name=file_name, content=content)
        else:
            print("\n There is no such file on your cloud")
    except Exception as e:
        print("Decrypt operation is failed")
        print(e)


def welcome_connection(trials):
    ssh_ip = input("\tServer IP: ")
    ssh_user = input("\tSSH Username: ")
    print("\tWhile you are typing password, it won't show up due to security reasons. No worries..")
    ssh_password = getpass.getpass(prompt='\tSSH Password: ', stream=None)
    trials = trials

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_ip, username=ssh_user, password=ssh_password)
        sftp = ssh.open_sftp()
        return ssh, sftp
    except Exception as e:
        if trials == 2:
            print("Your %drd attempt, process is ended" % trials+1)
            print(e)
            exit(0)
        trials += 1
        print("Couldn't connect to server, try again.")
        welcome_connection(trials)


def print_items():
    if current_files:
        print("\n Your current files stored on the cloud:")
        for current_file in current_files:
            print("\n\t - %s" % current_file)
    else:
        print("\n You do not store any files on the cloud")


def upload_file(file_name, content):
    try:
        file = sftp.file(file_name + ".dat", "wb", -1)
        file.write(content)
        file.flush()
        sftp.close()
        ssh.close()
    except Exception as e:
        print("Upload operation is failed")
        print(e)


def download_file(file_name):
    try:
        content = sftp.open(file_name)
        cipher = ""
        for c in content:
            cipher += c
        return cipher
    except Exception as e:
        print("File download operation is failed")
        print(e)


def create_file(file_name, content):
    try:
        file = open(file_name, 'wb+')
        file.write(content)
        file.close()
        print("Your file is downloaded!")
    except Exception as e:
        print("File creating operation is failed")
        print(e)


def delete_file(file_name):
    try:
        if file_name in current_files:
            sftp.remove(file_name)
            current_files.remove(file_name)
        else:
            print("No such file to delete")
    except Exception as e:
        print("Delete operation failed")
        print(e)


trials = 0
username = getpass.getuser()
print("\nWelcome to simpleStorage\n")
ssh, sftp = welcome_connection(trials)
current_files = get_items()


print("\n\nHello %s,\n"
      "You can encrypt/decrypt files created by YOU\n"
      "Commands:"
      "\n\t - items : Get the list of files stored on cloud"
      "\n\t - items! : Get the list of files stored on cloud"
      "\n\t - store <path_of_the_file> : Encrypt your local file and store it on the cloud"
      "\n\t - get <name_of_the_file_in_the_list> : Download and recreate your encrypted file to current directory"
      "\n\t - delete <name_of_the_file_in_the_list> : Delete a file from your cloud"
      "\n\t - exit : Obvious.."
      % username)

print_items()

while True:
    raw_command = input("> ")
    raw_command = raw_command.split(" ")
    command = raw_command[0]
    if len(raw_command) > 1:
        parameter = raw_command[1]

    if command == "items":
        print_items()
    elif command == "items!":
        current_files = get_items()
        print_items()
    elif command == "store":
        encrypt_file(file_path=parameter)
    elif command == "get":
        decrypt_file(file_name=parameter)
    elif command == "delete":
        delete_file(file_name=parameter)
    elif command == "exit":
        print("Bye")
        exit(0)
    else:
        print("Undefined command!")
