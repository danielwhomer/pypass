# pypass

pypass is a simple command line tool for maintaining a password database.

Available functionality:

--add
Adds a password (name, and password value) to the database

--remove
Remove a password from the database

--search term
Searches the database and returns all entries that match the specified term
Example: pypass.py --search Amazon


Security features:
The database is saved to an encrypted file (Fernet encryption).
Plaintext information is never present in non-volatile memory. It's assumed that if an attacker had the ability to access volatile memory, you have bigger problems to worry about.
