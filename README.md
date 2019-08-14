# pypass

pypass is a simple command line tool for maintaining a password database.

Available functionality:

--add
Adds a password (name, and password value) to the database


Security features:
The database is saved to an encrypted file (Fernet encryption).
Plaintext information is never present in non-volatile memory. It's assumed that if an attacker had the ability to access volatile memory, you have bigger problems to worry about.
