import argparse
import os
import random
import struct
import json
import getpass
from cryptography.fernet import Fernet
import secrets
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d



class CryptoDB():
	def __init__(self, _file):
		self._file = _file
		self.contents = ""
		self.pwdlist = {}
		self.iterations = 100_000
		self.backend = default_backend()
	
	def add_password(self, name, password):
		#need to check if name already exists		
		self.pwdlist[name] = password

	 
	def _derive_key(self, password: bytes, salt: bytes, iterations: int = 100_000) -> bytes:
		#Derive a secret key from a given password and salt
		kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations,backend=self.backend)
		return b64e(kdf.derive(password))

	def password_encrypt(self, password: str, iterations: int = 100_000) -> bytes:
		self.contents ="{\"passwords\":["
		for pwd in self.pwdlist:
			self.contents = self.contents + json.dumps({"name": pwd, "password": self.pwdlist[pwd]}) + ','
		self.contents = self.contents[:-1]
		self.contents += "]}"
		
		salt = secrets.token_bytes(16)
		key = self._derive_key(password.encode(), salt, self.iterations)
		data = b64e( 
							b'%b%b%b' % (
								salt,
								iterations.to_bytes(4,'big'),
								b64d(Fernet(key).encrypt(self.contents.encode())),
							)
					)
		self.save_to_file(self._file, data)

	def parse_json(self, data):
		parse = json.loads(data)
		print(parse)
		for pwd in parse['passwords']:
			self.add_password(pwd['name'], pwd['password'])
			
		
	def password_decrypt(self, token: bytes, password: str) -> bytes:
		decoded = b64d(token)
		salt, iter, token = decoded[:16], decoded[16:20], b64e(decoded[20:])
		iterations= int.from_bytes(iter, 'big')
		key = self._derive_key(password.encode(), salt, iterations)
		return Fernet(key).decrypt(token)

	def get_salt(self, token: bytes) -> bytes:
		decoded = b64d(token)
		salt = decoded[:16]
		return salt

	def get_token(self, data: bytes) -> bytes:
		decoded = b64d(data)
		token = b64e(decoded[20:])
		return token

	def save_to_file(self, _file, data):
		with open(self._file, 'wb') as f:
			f.write(data)

	def load_from_file(self, _file):
		if not _file:
			_file = self._file

		with open(_file, 'rb') as f:
			data = f.read()
		self.contents = data
		return data
		

class Password():
	def __init__(self, name, value):
		self.name = name
		self.value = value

	def get_value(self):
		return self.value

	def get_name(self):
		return self.name

"""---------------------GUI Definitions--------------------------------"""
def input_password():
	pass_name = input('Enter name of password: ')
	try:
		pass_value = getpass.getpass(prompt='Enter the password: ')
	except Exception as error:
		print('ERROR', error)
	else:
		return pass_name, pass_value

def input_key() -> bytes:
	key = pass_value = getpass.getpass(prompt='Enter the master key for the database: ')
	return bytes('passwordpassword', 'utf-8')

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Python Password Database')
	parser.add_argument('--file', action='store', type=str, default='pwdlist.json.enc', help='The file location of the encrypted database')
	parser.add_argument('--get', action='store', type=str, help='Return the password value for a given name')
	parser.add_argument('--search', action='store', type=str, help='Search for a password')
	parser.add_argument('--add', action='store_true', help='Add a new password to the database')
	args = parser.parse_args()

	c = CryptoDB(args.file)
	data = c.load_from_file('pwdlist.json.enc')
	token = c.get_token(b64e(data))	
	print('initial token:')	
	print(token)
	salt = c.get_salt(token)
	print('\n' + 'initial salt:')	
	print(salt)
	password = 'passwordpassword'	

	d = c.password_decrypt(data, password).decode()
	c.parse_json(d)


	if args.add:
		name,value = input_password()
		c.add_password(name, value)
	c.add_password('test2', 'test2')

	c.password_encrypt(password)



