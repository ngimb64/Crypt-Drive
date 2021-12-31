import os

def initialize():
    global dir_check, file_check, db_create, db_insert, db_retrieve

    dir_check = lambda path: os.path.isdir(path)
    file_check = lambda path: os.path.isfile(path)
    db_create = lambda db: f'CREATE TABLE {db}(name VARCHAR(20) PRIMARY KEY NOT NULL, item TEXT NOT NULL);'
    db_insert = lambda db, name_val, item_val: f'INSERT INTO {db} (name, item) VALUES (\"{name_val}\",\"{item_val}\");'
    db_retrieve = lambda db, name: f'SELECT name,item FROM {db} WHERE name=\"{name}\";'