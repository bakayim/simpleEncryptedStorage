
## What is simpleEncryptedStorage? ##

simpleEncryptedStorage lets you encrypt (AES-CBC Mode) your files (you must be owner of the files) and store them on the cloud (you must have an SSH connection to your server)

At the beginning, the program will ask you IP, user and password to make SSH connection.

When you want to encrypt and store a file, program will ask you a password to encrypt/decrypt it.  
**Do not forget your password for each file.** **If you forget** which password you entered to encrypt a file, **you cannot decrypt** it.

You will have six commands to use the program:

`> items` 
Shows the list of your files on the cloud  

`> items!` 
Shows the list of your files on the cloud after hard refresh  

`> store myPhoto.png` 
Encrypts your file, upload it to cloud, remove it from your local system  

`> get myPhoto.png` 
Downloads your file from cloud, decrypts it, creates it in your local system  

`> delete myPhoto.png` 
Deletes the file from your cloud (Before issuing this command, be sure you downloaded the file or you will lose it) 

`> exit` 
Quit program

## Installation ##

 Create a virtual environment (Python 3.6)  
 Install python packages by issuing `pip install -r requirements.txt`  
 Open your virtual environment folder, go to *lib/python3.6/site-packages* - Change 'crypto' to 'Crypto' (Make it uppercase)   
 Run the program, `python main.py`

## Disclaimer ##

I did not test it with large files yet, so I don't know how big files are supported.  
Sometimes program may crash due to unknown reason, I will try to figure it out following days. Do not hesitate to give a hand. 

Thank you, Batuhan KAYIM

## Sources ##

AESCipher Class is taken from this [gist](https://gist.github.com/forkd/168c9d74b988391e702aac5f4aa69e41) and modified a bit
