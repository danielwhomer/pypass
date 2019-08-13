import argparse
import os
import random
import struct
import json
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random


class CryptoDB():
	def __init__(self, _file):
		self._file = _file
		self.contents = ""
		self.pwdlist = {}
	
	def add_password(self, name, password):
		#need to check if name already exists		
		self.pwdlist[name] = password


	def encrypt(self, key, chunksize=64*1024):
		out_filename = self._file + '.enc'

		iv = os.urandom(16)		
		encryptor = AES.new(key, AES.MODE_CBC, iv)
		filesize = os.path.getsize(self._file)
	
		self.contents ="{\"passwords:["
		for pwd in self.pwdlist:
			self.contents += json.dumps({"name": pwd, "password": self.pwdlist[pwd]})
		self.contents += "]}"

		print(self.contents)

		
		#with open(self._file, 'rb') as infile:
			#with open(out_filename, 'wb') as outfile:
				#outfile.write(struct.pack('<Q', filesize))
				#outfile.write(iv)

				#while True:
					#chunk = infile.read(chunksize)
					#if len(chunk) == 0:
						#break
					#elif len(chunk) % 16 != 0:
						#chunk += ' '.encode('utf-8') * (16 - len(chunk) % 16)

					#outfile.write(encryptor.encrypt(chunk))
	
	def decrypt(self, key, chunksize=24*1024):
		#Currently decrypts a file, plan is to change to decrypt data in volatile memory
		out_filename = os.path.splitext(self._file)[0]

		with open(self._file, 'rb') as infile:
			origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
			iv = infile.read(16)
			decryptor = AES.new(key, AES.MODE_CBC, iv)
			
			decrypted_data = ""
			while True:
				chunk = infile.read(chunksize)
				if len(chunk) == 0:
					break
				decrypted_data += decryptor.decrypt(chunk).decode()
			decrypted_data = decrypted_data[:origsize]

		#self.contents = json.loads(decrypted_data)
		self.contents = decrypted_data
		

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
	
	c.encrypt(key)
