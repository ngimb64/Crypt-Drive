# Crypt Drive
![alt text](https://github.com/ngimb64/Crypt-Drive/blob/main/CryptDrive.png?raw=true)

&#9745;&#65039; Bandit verified<br>
&#9745;&#65039; Synk verified<br>
&#9745;&#65039; Pylint verified

## Prereqs
Made for Windows and Linux, written in Python 3.9

## Purpose
Crypt Drive is designed to manage encrypted uploads to cloud storage (Google Drive), store keys in a password
protected database, while giving the user to share the unlock key & nonce via a temporary password protected
encryption through emails & a password provided via sms text message. After unlock components are received
the user downloads the shared encrypted data from drive and uses the program to import the key then decrypt it.
Crypt Drive also is able to store and rebuild recursive file systems through encrypted databases.

It also features a startup script that check the programs components such as keys and databases. If components are
missing, the program checks the recycling bin and file system in an attempt to recover it. If the recovery fails,
new components are created and the data must be re-uploaded with the new key set to be able to decrypt it.

## Installation
- Run the setup.py script to build a virtual environment and install all external packages in the created venv.

> Example: `python3 setup.py venv`

- Once virtual env is built traverse to the (Scripts-Windows or bin-Linux) directory in the environment folder just created.
- For Windows in the Scripts directory, for execute the `./activate` script to activate the virtual environment.
- For Linux in the bin directory, run the command `source activate` to activate the virtual environment.


- Create a gmail account or login to existing account.
- Follow these steps but for step 5 create OAuth 2.0 Client ID instead of api keys 
  https://support.google.com/googleapi/answer/6158862/setting-up-api-keys?hl=en
- Click on the created OAuth 2.0 Client ID then copy the Client ID & Client secret to the settingsTemplate.yaml
  file where specified, which saves credentials after the first use of api. Then rename the file to settings.yaml.
- Once the API credentials are saved, turn in two-factor authentication in security settings in google account. After
  that is set, an Application Password can be generated in Google account settings and need to be saved in the base
  directory in CryptDrive as a file named AppSecret.txt.
- The API credentials are for Drive authentication and the AppSecret.txt is for Gmail authentication.

### Encryption scheme:
- Database Unlock & Sharing - Authenticated AES 256 counter mode CBC with 104 bit nonce & CBC-MAC (CCM) integrity check
- Local database - Fernet AES 128 CBC mode with PKCS7 padding & HMAC integrity check
- Data encrypt / decrypt - ChaCha20 256 with 128 bit nonce

## How to use
- Enter password to create key/database set, if they already exist the db encryption key is unlocked
- A startup script is run to confirm critical components exist, recreates anything missing

### Upload
- Enter path to file in the instructed format
- The default web browser should pop up with a Google login page
- After completing authentication the credentials should be saved to a credentials.json file which prevents
  having to log in for future use
- Upload process should initiate & finish in a timely manner

### Sharing Keys
- Simply enter the prompted questions and the rest will be handled
- Preferably obtain two separate email accounts (one being an encrypted provider like Protonmail or Tutanota) & a
  phone number of the person to share keys, nonce, & password with
- One email account can be used for both emails, but it reduces the security while requiring less effort to intercept
  and crack the encryption

### Import
- Download the files from both emails which should be two keys and a corresponding nonce for each key
- Move all 4 files into the Import folder
- Enter the username of the email account the keys were sent from
- Enter the password provided in the sms text message

### Decryption
- Download shared cloud drive data
- Move encrypted data into DecryptDock folder
- Make sure the user's decryption keys have been imported
- Enter username to decrypt data or enter to decrypt your own data

## Function Layout


## Exit Codes
-- cryptDrive.py --

0 - Successful operation <br>
1 - Error occurred during program startup <br>
2 - User has exhausted maximum password attempts <br>
3 - Error occurred decrypting keyring in startup <br>

-- AuthCrypt.py --

4 - Error decrypting the cipher hashed secret <br>
5 - Error decrypting the database Fernet key <br>

-- Utils.py --

6 - Error decrypting database data <br>
7 - Error encrypting database data <br>
8 - Maximum (3) consecutive IO errors occurred <br>
9 - Error occurred writing to encrypted log file <br>
