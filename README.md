# Crypt Drive
![alt text](https://github.com/ngimb64/Crypt-Drive/blob/main/CryptDrive.png?raw=true)
![alt text](https://github.com/ngimb64/Crypt-Drive/blob/main/Crypt_Drive.png?raw=true)

&#9745;&#65039; Bandit verified<br>
&#9745;&#65039; Synk verified<br>
&#9745;&#65039; Pylint verified 9.91/10

## Prereqs
Made for Windows and Linux, written in Python 3.9

## Purpose
Crypt Drive is designed to manage encrypted uploads to cloud storage (Google Drive), store keys in a
password protected database, while giving the user to share the unlock key & nonce via a temporary 
password protected encryption through emails & a password provided via sms text message. After 
unlock components are received the user downloads the shared encrypted data from drive and uses the 
program to import the key then decrypt it. Crypt Drive also is able to store and rebuild recursive 
file systems through encrypted databases.

It also features a startup script that check the programs components such as keys and databases. If 
components are missing, the program checks the recycling bin and file system in an attempt to 
recover it. If the recovery fails, new components are created and the data must be re-uploaded with 
the new key set to be able to decrypt it.

## Installation
- Run the setup.py script to build a virtual environment and install all external packages in the created venv.

> Example: `python3 setup.py venv`

- Once virtual env is built traverse to the (Scripts-Windows or bin-Linux) directory in the environment folder just created.
- For Windows in the Scripts directory, for execute the `./activate` script to activate the virtual environment.
- For Linux in the bin directory, run the command `source activate` to activate the virtual environment.

- Create a gmail account or login to existing account.
- Follow these steps but for step 5 create OAuth 2.0 Client ID and secret in Google Cloud instead 
  of api keys https://support.google.com/googleapi/answer/6158862/setting-up-api-keys?hl=en
- Click on the created OAuth 2.0 Client ID then copy the Client ID & Client secret to the 
  settingsTemplate.yaml file where specified, which saves credentials after the first use of api. 
  Then rename the file to settings.yaml.
- Once the API credentials are saved, turn on two-factor authentication in security settings in 
  google account. After that is set, an Application Password can be generated in Google account 
  settings and need to be saved in the base directory in CryptDrive as a file named AppSecret.txt.
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
-- crypt_drive.py --
> main_menu &nbsp;-&nbsp; Display command options and receives input on what command to execute.

> start_check &nbsp;-&nbsp; Confirms program components are preset. If missing, component recovery 
> is attempted. If that fails results in the creation of a fresh set of components.

> password_input &nbsp;-&nbsp; Receive password input from user, verify with Argon2 hashing
> algorithm or create new password in none exist.

-- auth_crypt.py --
> AuthCrypt &nbsp;-&nbsp; Class to manage cryptographic components.<br>
> &emsp; get_plain_secret &nbsp;-&nbsp; Decrypt the encrypted hash secret.<br>
> &emsp; decrypt_db_key &nbsp;-&nbsp; Decrypt the database key with aesccm authenticated.

-- globals.py -- 
> initialize &nbsp;-&nbsp; Initializes variables for global access.

> dir_check &nbsp;-&nbsp; Check if directory exists.

> file_check &nbsp;-&nbsp; Check if file exists.

> db_keys &nbsp;-&nbsp; Format MySQL query for Keys database table creation.

> db_storage &nbsp;-&nbsp; Format MySQL query for Storage database table creation.

> db_insert &nbsp;-&nbsp; Format MySQL query to insert keys in the keys database.

> db_store &nbsp;-&nbsp; Format MySQL query to insert data into the storage database.

> db_retrieve &nbsp;-&nbsp; Format MySQL query to retrieve item from database.

> db_contents &nbsp;-&nbsp; Format MYySQL query to retrieve the contents of a database.

> db_delete &nbsp;-&nbsp Format MySQL query to delete an item from a database.

-- menu_functions.py --
> db_extract &nbsp;-&nbsp; Extracts data from local storage database in encrypted or plain text.

> db_store &nbsp;-&nbsp; Encrypts and inserts data into storage database.

> decryption &nbsp;-&nbsp; Decrypts data located on the file system.

> file_upload &nbsp;-&nbsp; Recursively uploads files to Drive.

> folder_upload &nbsp;-&nbsp; Recursively uploads folders to Drive.

> import_key &nbsp;-&nbsp; Import user's key to the encrypted local key database.

> list_drive &nbsp;-&nbsp; List the contents of Google Drive storage.

> list_storage &nbsp;-&nbsp; List the contents of the local storage database.

> key_share &nbsp;-&nbsp; Share decryption key protected by a password through authentication-based 
> encryption.

> upload &nbsp;-&nbsp; Manages encrypted recursive upload to Google Drive.

-- menu_utils.py --
> decrypt_input &nbsp;-&nbsp; Gathers users input for database data decryption function.

> extract_input &nbsp;-&nbsp; Gathers users input for database data extraction function.

> extract_parse &nbsp;-&nbsp; Attempts to match regex of recursive path on stored file path in 
> extracted database row. If match fails, document is extracted to base directory entered in 
> non-recursive fashion. If stored filepath is formatted as opposing OS, reformat it to current OS.

> import_input &nbsp;-&nbsp; Gathers users input for key import function.

> meta_handler &nbsp;-&nbsp; Formats file path whether in recursive directory or not depending on \
> OS. Passes formatted file path into meta_strip function to strip the file metadata.

> share_input &nbsp;-&nbsp; Gathers users input for key share function.

> store_input &nbsp;-&nbsp; Gathers users input for database data storage function.

> upload_dir_handler &nbsp;-&nbsp; Ensures the full path to the passed in directory name is created.

> upload_extract &nbsp;-&nbsp; Extracts, decodes, and writes storage database contents to upload
> dock for cloud drive upload.

> upload_input &nbsp;-&nbsp; Gathers users input for data upload to cloud drive.

> upload_stage &nbsp;-&nbsp; Makes of copy of file data to be uploaded in the UploadDock folder.

-- utils.py --
> cha_init &nbsp;-&nbsp; Initializes the ChaCh20 algorithm object.

> cha_decrypt &nbsp;-&nbsp; Retrieve ChaCha components from Keys db, decoding and decrypting them.

> CompiledRegex &nbsp;-&nbsp; Class for grouping numerous compiled regex.

> component_handler &nbsp;-&nbsp; Creates various dir, db, and key components required for program 
> operation.

> create_databases &nbsp;-&nbsp; Creates database components.

> create_dirs &nbsp;-&nbsp; Creates program component directories.

> data_copy &nbsp;-&nbsp; Copies data from source to destination.

> db_check &nbsp;-&nbsp; Checks the upload contents within the keys database and populates 
> authentication object.

> decrypt_db_data &nbsp;-&nbsp; Decodes and decrypts database base64 cipher data.

> dir_recover &nbsp;-&nbsp; Iterates through list of passed in dirs and checks to see if current 
> folder is the same name to static assignment.

> encrypt_db_data &nbsp;-&nbsp; Encrypts and encodes plain data for database.

> error_query &nbsp;-&nbsp; Looks up the errno message to get description.

> fetch_upload_comps &nbsp;-&nbsp; Retrieves upload components from keys database.

> file_handler &nbsp;-&nbsp; Error validated file handler for read and write operations.

> file_recover &nbsp;-&nbsp; Checks to see if current iteration of os walk is the file to be 
> recovered.

> get_database_comp &nbsp;-&nbsp; Unlock and retrieve database cryptography component.

> hd_crawl &nbsp;-&nbsp; Recursive hard drive crawler for recovering missing components.

> key_recreate &nbsp;-&nbsp; Recreates key or nonce and insert them back into param db_name 
> database named as store_comp.

> logger &nbsp;-&nbsp; Encrypted logging system.

> login_timeout &nbsp;-&nbsp; Displays loging timeout per second for 60 second interval.

> log_err &nbsp;-&nbsp; Logs error or exception based on passed in handler parameter.

> log_read &nbsp;-&nbsp; Reads input text page by page, displaying 60 lines per page.

> make_keys &nbsp;-&nbsp; Creates a fresh cryptographic key set, encrypts, and inserts in keys 
> database.

> meta_strip &nbsp;-&nbsp; Attempts striping metadata from passed in file. If attempt fails, 
> waiting a second and tries again while adding a second of waiting time per failure. After 3 
> failed attempts, it returns a False boolean value.

> msg_format &nbsp;-&nbsp; Format email message headers and attach passed in files.

> msg_send &nbsp;-&nbsp; Facilitate the sending of formatted emails.

> print_err &nbsp;-&nbsp; Displays error message via stderr for supplied time interval.

> query_handler &nbsp;-&nbsp; Facilitates MySQL database query execution.

> recycling_bin &nbsp;-&nbsp; Checks the recycling bin for missing program components.

> secure_delete &nbsp;-&nbsp; Overwrite file data with random data number of specified passes and 
> delete.

> system_cmd &nbsp;-&nbsp; Execute shell-escaped command.

> sys_lock &nbsp;-&nbsp; Attempts to lockdown (Windows) or power-off system (Linux), if either fail 
> the program exits with error code.

> write_log &nbsp;-&nbsp; Parse new log message to old data and write encrypted result to log.

## Exit Codes
-- crypt_drive.py --
0 - Successful operation <br>
1 - Error occurred during program startup <br>
3 - Error occurred decrypting keyring in startup (password_input)<br>

-- auth_crypt.py --
5 - Error decrypting the cipher hashed secret (get_plain_secret)<br>
6 - Error decrypting the database Fernet key (decrypt_db_data)<br>

-- utils.py --
2 - User has exhausted maximum password attempts (sys_lock)<br>
4 - Error decryption local database key (db_check)<br>
7 - Error decrypting database data (decrypt_db_data)<br>
8 - Error encrypting database data (encrypt_db_data)<br>
9 - Maximum (3) consecutive IO errors occurred (file_handler)<br>
10 - Error occurred writing to encrypted log file (write_log)<br>
