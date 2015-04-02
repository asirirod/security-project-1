import json, pprint
import base64, binascii, os
import pbkdf2
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA 

class FileManager():

	def __init__(self):
		self.users = {}
		self.roles = {}
		self.files = {}

	############  User Functions  ############

	def create_user(self, username, password):
		salt = "salt"
		user_data = {
			"salted_password": self.generate_PBKDF2_key(password, salt),
			"encrypted_role_private_keys": [],
	        "salt": salt
		}

		self.users[username] = user_data

	def add_user_to_role(self, username, role_name):
		# Add new role to user data
		role_info = role_name + ":" + self.get_role_public_key(role_name)
		encrypted_info = self.encrypt_with_AES(self.users[username]['salted_password'], role_info)
		self.users[username]["encrypted_role_private_keys"].append(encrypted_info)

		# Add new user to role data
		self.roles[role_name]['users'].append(username)

	def get_user_role(self):
		pass

	############  Role Functions  ############

	def create_role(self, role_name):
		role_data = {
			"key" : self.generate_RSA_Key(),    # Get Private Key
			"users" : []
		}

		self.roles[role_name] = role_data

	def get_role_public_key(self, role_name):
		key = RSA.importKey(self.roles[role_name]['key'])
		return key.publickey().exportKey()

	def unlock_role(self, username, password, role):
		pass

	############  File Functions  ############

	def create_file(self, filename, role, data):
		file_data = {
			"data": data,
			"roles": []
		}

	def add_role_to_file(self, filename):
		pass

	def lock_file(self, username, password, filename):
		pass

	############  Key Functions  ############

	def get_random_key(self):
		key = os.urandom(16)
		key = binascii.hexlify(key)
		return key

	def generate_PBKDF2_key(self, message, salt, iterations=1000):
		pbkdf2_key = pbkdf2.PBKDF2(message, salt, iterations).read(32)
		pbkdf2_key = binascii.hexlify(pbkdf2_key)
		return pbkdf2_key

	def encrypt_with_AES(self, key, message):
		key = binascii.unhexlify(key)

		PADDING = '{'
		BLOCK_SIZE = 16

		# one-liner to sufficiently pad the text to be encrypted
		pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

		# one-liners to encrypt/encode and decrypt/decode a string
		# encrypt with AES, encode with base64
		EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
		DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
		aes_obj = AES.new(key)

		cyphertext = EncodeAES(aes_obj, message)
		return cyphertext

	def decrypt_with_AES(self, key, encrypted_message):
		key = binascii.unhexlify(key)

		PADDING = '{'
		BLOCK_SIZE = 16
		# one-liner to sufficiently pad the text to be encrypted
		pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

		# one-liners to encrypt/encode and decrypt/decode a string
		# encrypt with AES, encode with base64
		EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
		DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
		aes_obj = AES.new(key)

		message = DecodeAES(aes_obj, encrypted_message)
		return message

	def generate_RSA_Key(self, bits=1024):
		rsa_key = RSA.generate(bits)
		# public_key = rsa_key.publickey().exportKey("PEM")
		# private_key = rsa_key.exportKey("PEM")
		return rsa_key.exportKey("PEM")

	def encrypt_with_RSA_key(self, key, message):
		encoded_msg = key.encrypt(message, None)[0]
		encoded_msg_b64 = base64.encodestring(encoded_msg)
		print "RSA encoded msg is '%s'" % encoded_msg_b64
		return encoded_msg_b64

	def decrypt_with_RSA_key(self, key, encoded_message):
		msg = base64.decodestring(encoded_message)
		msg = key.decrypt(msg)
		print "RSA decoded msg is '%s'" % msg
		return msg

	############  File Functions  ############

	def write_data_to_file(self, filename, data):
		with open(filename, 'w') as outfile:
			json.dump(data, outfile, indent=4, sort_keys=True)

	def read_data_from_file(self, filename):
		with open(filename, 'r') as handle:
			parsed = json.load(handle)

		return parsed

if __name__ == '__main__':

	filemgr = FileManager();

	filemgr.create_role("beginner")
	filemgr.create_role("intermediate")
	filemgr.create_role("advanced")

	filemgr.create_user("joe", "joe")
	filemgr.create_user("bob", "bob")
	filemgr.create_user("bill", "bill")

	filemgr.add_user_to_role("bob", "beginner")

	# Print info
	print "Users: %s\n" % json.dumps(filemgr.users, indent=4, sort_keys=True)
	print "Roles: %s\n" % json.dumps(filemgr.roles, indent=4, sort_keys=True)

	exit()

	print "\n================= PBKDF2 ================\n"

	pb_key = filemgr.generate_PBKDF2_key("This passphrase is a secret.", "salt")
	print "PBKDF2 Key: %s" % pb_key

	print "\n================== AES ================\n"

	ct = filemgr.encrypt_with_AES(pb_key, "This is my message")
	print "Cypher: %s" % ct
	pt = filemgr.decrypt_with_AES(pb_key, ct)
	print "Plain: %s" % pt

	print "\n================= RSA ================\n"
	priv = filemgr.generate_RSA_Key()
	print priv
	pk = RSA.importKey(priv)
	print pk.publickey().exportKey("PEM")

	enc = filemgr.encrypt_with_RSA_key(pk, "THIS IS MY SECRET MESSAGE")

	filemgr.decrypt_with_RSA_key(pk, enc)

	print "\n================= FILE I/O ================\n"
	filemgr.write_data_to_file("test.txt", filemgr.users)
	d = filemgr.read_data_from_file("test.txt")
	print "D: %s" % json.dumps(d, indent=4, sort_keys=True)

	loop = 0
	while loop == 1:
		print "\n==================================\n"
		print "OPTIONS:\n 1: Exit\n 2: Create User\n 3: Login as User\n"
		prompt = '> '
		print "Select option: "
		selection = raw_input(prompt)
		print("Selection: %s" % selection)

		selection = int(selection)

		if selection == 1:
			print("Exiting");
			loop = 0
		elif selection == 2:
			print "Add New File"
		elif selection == 3:
			print "Login as User"
