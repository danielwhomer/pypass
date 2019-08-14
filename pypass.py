import argparse
import os, sys
import random
import struct
import json
import getpass
import re
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
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
	
	def add_password(self, name: str, password: str):
		#need to check if name already exists		
		self.pwdlist[name] = password

	def remove_password(self, name: str):
		try:
			deleted = self.pwdlist.pop(name)
		except KeyError as e:
			print("ERROR: Password with name " + name + " not found.")

	def search_password(self, name: str):
		results = []		
		for key in self.pwdlist.keys():
			if name in key:
				results.append(key)
		return results
				
			
	def _derive_key(self, password: bytes, salt: bytes, iterations: int = None) -> bytes:
		if iterations is None:
			iterations = self.iterations
		#Derive a secret key from a given password and salt
		kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations,backend=self.backend)
		return b64e(kdf.derive(password))

	def password_encrypt(self, password: str, iterations: int = None) -> bytes:
		if iterations is None:
			iterations = self.iterations

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
		for pwd in parse['passwords']:
			self.add_password(pwd['name'], pwd['password'])
			
		
	def password_decrypt(self, token: bytes, password: str) -> bytes:
		decoded = b64d(token)
		salt, iter, token = decoded[:16], decoded[16:20], b64e(decoded[20:])
		iterations= int.from_bytes(iter, 'big')
		key = self._derive_key(password.encode(), salt, iterations)
		try:
			data = Fernet(key).decrypt(token)
		except InvalidToken as e:
			return None
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

	def load_from_file(self, _file = None):
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

"""---------------------UI Definitions--------------------------------"""
def input_password():
	pass_name = input('Enter name of password: ')
	try:
		pass_value = getpass.getpass(prompt='Enter the password: ')
	except Exception as error:
		print('ERROR', error)
	else:
		return pass_name, pass_value

def input_name():
	pass_name = input('Enter name of password: ')
	return pass_name

def input_key():
	key = pass_value = getpass.getpass(prompt='Enter the master key for the database: ')
	return pass_value

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Python Password Database')
	parser.add_argument('--file', action='store', type=str, default='pwdlist.json.enc', help='The file location of the encrypted database')
	parser.add_argument('--get', action='store', type=str, help='Return the password value for a given name')
	parser.add_argument('--search', '-s', action='store', type=str, help='Search for a password')
	parser.add_argument('--add','-a', action='store_true', help='Add a new password to the database')
	parser.add_argument('--remove','-r', action='store_true', help='Remove a password from the database')
	args = parser.parse_args()

	c = CryptoDB(args.file)
	data = c.load_from_file()
	token = c.get_token(b64e(data))	
	salt = c.get_salt(token)
	password = input_key()

	d = c.password_decrypt(data, password)
	if not d:
		print("Something went wrong. Did you enter the correct master key?")
		sys.exit()
	else:
		d = d.decode()
	c.parse_json(d)

	if args.add:
		name,value = input_password()
		c.add_password(name, value)
	
	if args.remove:
		name = input_name()
		c.remove_password(name)
	
	if args.search:
		search = args.search
		results = c.search_password(search)
		if not results:
			print("No passwords found for search term " + search + ".")
		else:
			print("The following entries were found:")
			for result in results:
				print(result)

	c.password_encrypt(password)



