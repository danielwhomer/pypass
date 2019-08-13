import argparse
import os
import random
import struct
import json
#from Crypto.Cipher import AES
#from Crypto.Hash import SHA256
#from Crypto import Random
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

	def password_encrypt(self, message: bytes, password: str, iterations: int = 100_000) -> bytes:
		self.contents ="{\"passwords:["
		for pwd in self.pwdlist:
			self.contents += json.dumps({"name": pwd, "password": self.pwdlist[pwd]})
		self.contents += "]}"
		
		salt = secrets.token_bytes(16)
		key = self._derive_key(password.encode(), salt, self.iterations)
		return b64e( 
							b'%b%b%b' % (
								salt,
								iterations.to_bytes(4,'big'),
								b64d(Fernet(key).encrypt(self.contents.encode())),
							)
					)

	def password_decrypt(self, token: bytes, password: str) -> bytes:
		decoded = b64d(token)
		salt, iter, token = decoded[:16], decoded[16:20], b64e(decoded[20:])
		iterations= int.from_bytes(iter, 'big')
		key = self._derive_key(password.encode(), salt, iterations)
		return Fernet(key).decrypt(token)

	def load_from_file(self, _file, token, password):
		if not _file:
			_file = self._file

		with open(_file, 'rb') as f:
			data = f.read()

		self.contents = self.password_decrypt(token, password).decode()
		print(self.contents)
		

class Password():
	def __init__(self, name, value):
		self.name = name
		self.value = value

	def get_value(self):
		return self.value

	def get_name(self):
		return self.name

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Python Password Database')
	parser.add_argument('--file', action='store', type=str, default='pwdlist.json.enc', help='The file location of the encrypted database')
	parser.add_argument('--get', action='store', type=str, help='Return the password value for a given name')
	parser.add_argument('--search', action='store', type=str, help='Search for a password')
	args = parser.parse_args()

	c = CryptoDB(args.file)
	c.add_password('test1', 'testpwd1')
	c.add_password('test2', 'testpwd2')
	key = bytes('passwordpassword', 'utf-8')
	message = c.contents
	password = 'passwordpassword'

	token = c.password_encrypt(message.encode(), password)
	c.load_from_file('pwdlist.json.enc',token, password)



