import argparse
import getpass
import hashlib
import os
import sys

def main():
	args = argparse.ArgumentParser()
	args.add_argument('-d','--direct',help='direct',metavar='')

	group = args.add_mutually_exclusive_group()
	group.add_argument('--decrypt',help='scan site Using: --scan -u [url] ',action="store_true")
	args = args.parse_args()

	def encrypt():
		password = getpass.getpass()
		print(args.direct)
		hash_object = hashlib.md5(args.direct.encode()+password.encode()).hexdigest()
		f = open("passwords.pswd","w").write(hash_object)
		def crypt(file,passwords):
			import pyAesCrypt
			print("---------------------------------------------------------------" )
			password = passwords	
			bufferSize = 512*1024
			pyAesCrypt.encryptFile(str(file), str(file)+".crp", password, bufferSize)
			print("[crypted] '"+str(file)+".crp'")
			os.remove(file)
		def walk(dir):
			for name in os.listdir(dir): 
				path = os.path.join(dir, name)
				if os.path.isfile(path): crypt(path,password)
				else: walk(path)
		walk(args.direct)
		print("---------------------------------------------------------------" )

	def big_decrypt():
		password = getpass.getpass()
		def decrypt(file,passwd):
			import pyAesCrypt
			print("---------------------------------------------------------------" )
			password = passwd
			hash_object = hashlib.md5(args.direct.encode() + password.encode()).hexdigest()
			f = open("passwords.pswd",'r').read()
			if f == hash_object:
				print(True)
				bufferSize = 512*1024
				pyAesCrypt.decryptFile(str(file), str(os.path.splitext(file)[0]), password, bufferSize)
				print("[decrypted]"+str(os.path.splitext(file)[0]))
			else:
				print("Bad password")
				return decrypt()
		def walk(dir):
			for name in os.listdir(dir):
				path = os.path.join(dir, name)
				if os.path.isfile(path):
					try: decrypt(path,password)
					except: pass
				else: walk(path)
		walk(args.direct)
		os.remove(".crp")
		os.remove("passwords.pswd")

	if args.decrypt:
		big_decrypt()
	else:
		encrypt()
try:
	if __name__ == "__main__":
		main()
except:
	print("Usage:"+sys.argv[0]+" -h")