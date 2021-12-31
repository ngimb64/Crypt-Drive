# Crypt Drive

## Prereqs
- Python 3.9
- Cofirm all modules are installed .. attempt importing each module
- If a module import fails look up the package name & install via pip in command prompt
- If a installed module still fails confirm the correct package is installed .. some have very similar names

## Installation
- After Prereqs are completed
- Create a gmail account or login to existing account
- Follow these steps but for step 5 create OAuth 2.0 Client ID instead of api keys https://support.google.com/googleapi/answer/6158862/setting-up-api-keys?hl=en
- Click on the created OAuth 2.0 Client ID then copy the Client ID & Client secret to the settings.yaml file where specified .. which saves credentials after the first use of api

## Purpose
Crypt drive is designed manage encrypted uploads to cloud storage (Google Drive), store keys in a password protected database, while giving the user to share the unlock key & nonce via a temporary password protected encryption through emails & a password provided via sms text message. After unlock components are recieved the user downloads the shared encrypted data from drive and uses the program to import the key then decrypt it.

Local storage database will be added in the near future.

### Encryption scheme:
- Database Unlock & Sharing - Authenticated AES 256 counter mode CBC with 104 bit nonce & CBC-MAC (CCM) integrity check
- Local database - Fernet AES 128 CBC mode with PKCS7 padding & HMAC integrity check
- Data encrypt / decrypt - ChaCha20 256 with 128 bit nonce

## How to use
- Enter password to create key/database set .. if they aleady exist the db encryption key is unlocked
- A startup script is run to cofirm critical components exist .. recreates anything missing

### Upload
- After completing the prereqs & installation steps uploading should pretty simple
- Enter path to file as the recommended format C:\like\this\to\folder
- The default web browser should pop up with a google login page
- After completing authentication the credentials should be saved to a credentials.json file which prevents having to login for future use
- Upload process should initiate & finish in a timely manner

### Sharing Keys
- Simply enter the prompted questions and the rest will be handled
- Preferably obtain two separate email accounts (one being an encrypted provider like protonmail or tutanota) & a phone number of the person to share keys, nonce, & password with
- One email account can be used for both emails but it reduces the security while requiring less effort to intercept and crack the encryption

### Import
- Download the files from both emails which should be two keys and a corresponding nonce for each key
- Move all 4 files into the Import folder
- Enter the username of the email account the keys were sent from
- Enter the password provided in the sms text message

### Decryption
- Download shared cloud drive data
- Move encrypted data into DecryptDock folder
- Make sure the users decryption keys have been imported
- Enter username to decrypt data or enter to decrypt your own data