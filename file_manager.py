import traceback
import json, pprint
import base64, binascii, os
import pbkdf2
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA 
import hmac

class FileManager():

	def __init__(self, debug=1):
		self.users = {}
		self.roles = {}
		self.files = {}
		self.debug = debug

	############  User Functions  ############

	def create_user(self, username, password):
		salt = "salt"
		user_data = {
			"salted_password": self.generate_PBKDF2_key(password, salt),
			"encrypted_role_private_keys": [],
			# "password": password,
	        "salt": salt
		}

		self.users[username] = user_data

		# TODO: return false if user already exists

		return True

	def add_user_to_role(self, active_user, active_user_password, username, password, role_name):
		# Get Role Private Key from Active users role information.
		print " %s, %s, %s, %s, %s" % (active_user, active_user_password, username, password, role_name)
		role_private_key = self.get_role_private_key(active_user, active_user_password, role_name)
		if not role_private_key: print "Access Denied to role '%s'." % role_name; return False
		role_info = role_name + ":" + role_private_key

		password_key = self.generate_PBKDF2_key(password, self.users[username]['salt'])
		encrypted_info = self.encrypt_with_AES(password_key, role_info)	# self.users[username]['salted_password']
		self.users[username]["encrypted_role_private_keys"].append(encrypted_info)

		# Add new user to role data
		self.roles[role_name]['users'].append(username)

		return True

	def add_root_to_role(self, root_username, password, role_name, role_private_key):
		# Get Role Private Key from Active users role information.
		print "Adding Key %s" % role_private_key.exportKey("PEM")
		role_info = role_name + ":" + role_private_key.exportKey("PEM")

		password_key = self.generate_PBKDF2_key(password, self.users[root_username]['salt'])
		encrypted_info = self.encrypt_with_AES(password_key, role_info)
		self.users[root_username]["encrypted_role_private_keys"].append(encrypted_info)

		# Add new user to role data
		self.roles[role_name]['users'].append(root_username)

		return True

	def get_role_private_key(self, username, password, role_name):
		encrypted_role_keys = self.users[username]["encrypted_role_private_keys"]
		password_key = self.generate_PBKDF2_key(password, self.users[username]['salt'])
		for encrypted_role_key in encrypted_role_keys:
			decrypted_string = self.decrypt_with_AES(password_key, encrypted_role_key)
			print "role %s" %decrypted_string.split(":")[0]
			if (role_name == decrypted_string.split(":")[0]):
				return decrypted_string.split(":")[1]
		return None

	def get_user_roles(self, username, password):
		encrypted_role_keys = self.users[username]["encrypted_role_private_keys"]
		password_key = self.generate_PBKDF2_key(password, self.users[username]['salt'])
		roles = []
		for encrypted_role_key in encrypted_role_keys:
			decrypted_string = self.decrypt_with_AES(password_key, encrypted_role_key)
			roles.append(decrypted_string.split(":")[0])
		return roles

	def unlock_role(self, username, password, role_name):
		encrypted_role_keys = self.users[username]["encrypted_role_private_keys"]
		password_key = self.generate_PBKDF2_key(password, self.users[username]['salt'])
		for encrypted_role_key in encrypted_role_keys:
			decrypted_string = self.decrypt_with_AES(password_key, encrypted_role_key)
			if (role_name == decrypted_string.split(":")[0]):
				return self.roles[decrypted_string.split(":")[0]]
		return None

	def login(self, username, password):
		salted_password = self.generate_PBKDF2_key(password, self.users['root']['salt'])
		if self.debug: print "Given:    '%s'" % salted_password
		if self.debug: print "Expected: '%s'" % self.users[username]['salted_password']
		if salted_password == self.users[username]['salted_password']:
			return True
		return False

	############  Role Functions  ############

	def create_role(self, role_name):
		private_key = RSA.importKey(self.generate_RSA_Key())
		public_key = private_key.publickey().exportKey("PEM")
		role_data = {
			# "private_key": private_key.exportKey("PEM"),
			"key" : public_key,
			"users" : [],
		}

		self.roles[role_name] = role_data

		# Add root user to role
		if not self.add_root_to_role("root", "root", role_name, private_key):
			self.roles.pop(role_name)
			print "Failed to add root user to role."
			return False

		return True

	############  File Functions  ############

	def create_file(self, filename, role_name, role_public_key, content):
		file_key_1 = self.get_random_key()
		file_key_2 = self.get_random_key()

		role_public_key = RSA.importKey(role_public_key)

		encrypted_content = self.encrypt_with_AES(file_key_1, content)
		mac = hmac.new(file_key_2, data).digest().encode("base64")
		encrypted_keys = self.encrypt_with_RSA_key(role_public_key, file_key_1 + ":" + file_key_2)

		file_data = {
			#"fk1": file_key_1,
			#"fk2": file_key_2,
			# "content": encrypted_data,
			"mac": mac,
			"keys": {role_name : encrypted_keys}
		}

		file = open(filename, 'w')
		file.write(encrypted_content)
		file.close()

		self.files[filename] = file_data
		return True

	def read_file(self, filename, role_name, role_private_key):
		if filename not in self.files:
			print "File %s not found." % filename
			return None

		file = open(filename, 'r')
		encrypted_content = file.read()
		file.close()

		# Get File Keys
		file_keys = self.files[filename]['keys'][role_name]
		decrypted_keys = self.decrypt_with_RSA_key(RSA.importKey(role_private_key), file_keys)
		file_key_1 = decrypted_keys.split(":")[0]
		file_key_2 = decrypted_keys.split(":")[1]

		# Decrypt data using Key 1
		file_content = self.decrypt_with_AES(file_key_1, encrypted_content)

		# Generate HMAC with Key 2
		mac = hmac.new(file_key_2, file_content).digest().encode("base64")

		# Compare HMAC encryption with stored mac.
		if self.files[filename]['mac'] != mac:
			print "File content has been corrupted."
			return None

		return file_content

	def add_role_to_file(self, filename, role_name, role_public_key):
		# file_keys = self.files[filename]['keys'][role_name]
		# decrypted_keys = self.decrypt_with_RSA_key(RSA.importKey(unlock_role_key), file_keys)
		# file_key_1 = decrypted_keys.split(":")[0]
		# file_key_2 = decrypted_keys.split(":")[1]

		# role_public_key = RSA.importKey(role_public_key)

		# encrypted_content = self.encrypt_with_AES(file_key_1, content)
		# mac = hmac.new(file_key_2, data).digest().encode("base64")
		# encrypted_keys = self.encrypt_with_RSA_key(role_public_key, file_key_1 + ":" + file_key_2)

		# self.files[filename]['keys'][role_name] = encrypted_keys
		return True

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
		# DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
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
		# EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
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
		# print "RSA encoded msg is '%s'" % encoded_msg_b64
		return encoded_msg_b64

	def decrypt_with_RSA_key(self, key, encoded_message):
		msg = base64.decodestring(encoded_message)
		msg = key.decrypt(msg)
		# print "RSA decoded msg is '%s'" % msg
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

	debug = 1;

	filemgr = FileManager(debug);

	filemgr.users = filemgr.read_data_from_file("users.txt")
	filemgr.files = filemgr.read_data_from_file("files.txt")
	filemgr.roles = filemgr.read_data_from_file("roles.txt")

	# # Create Root account and give permissions.
	# filemgr.create_user("root", "root")

	# filemgr.create_role("beginner")
	# filemgr.create_role("intermediate")
	# filemgr.create_role("advanced")

	# filemgr.add_user_to_role("root", "root", "beginner")
	# filemgr.add_user_to_role("root", "root", "intermediate")
	# filemgr.add_user_to_role("root", "root", "advanced")

	# # filemgr.create_user("bob", "bob")
	# # filemgr.create_user("bill", "bill")

	# # filemgr.add_user_to_role("bob", "bob", "beginner")


	# # filemgr.create_file("beginner", "file1.txt", "this is file1 content.")

	# # Print info
	# print "Users: %s\n" % json.dumps(filemgr.users, indent=4, sort_keys=True)
	# print "Roles: %s\n" % json.dumps(filemgr.roles, indent=4, sort_keys=True)
	# print "Files: %s\n" % json.dumps(filemgr.files, indent=4, sort_keys=True)

	# filemgr.write_data_to_file("users.txt", filemgr.users)
	# filemgr.write_data_to_file("roles.txt", filemgr.roles)
	# filemgr.write_data_to_file("files.txt", filemgr.files)

	# exit()

	# print "\n================= PBKDF2 ================\n"

	# pb_key = filemgr.generate_PBKDF2_key("This passphrase is a secret.", "salt")
	# print "PBKDF2 Key: %s" % pb_key

	# print "\n================== AES ================\n"

	# ct = filemgr.encrypt_with_AES(pb_key, "This is my message")
	# print "Cypher: %s" % ct
	# pt = filemgr.decrypt_with_AES(pb_key, ct)
	# print "Plain: %s" % pt

	# print "\n================= RSA ================\n"
	# priv = filemgr.generate_RSA_Key()
	# print priv
	# pk = RSA.importKey(priv)
	# print pk.publickey().exportKey("PEM")

	# enc = filemgr.encrypt_with_RSA_key(pk, "THIS IS MY SECRET MESSAGE")

	# filemgr.decrypt_with_RSA_key(pk, enc)

	# print "\n================= FILE I/O ================\n"

	# filemgr.write_data_to_file("users.txt", filemgr.users)
	# filemgr.users = filemgr.read_data_from_file("test.txt")
	# print "USERS: %s" % json.dumps(filemgr.users, indent=4, sort_keys=True)

	# filemgr.write_data_to_file("roles.txt", filemgr.roles)
	# filemgr.roles = filemgr.read_data_from_file("roles.txt")
	# print "ROLES: %s" % json.dumps(filemgr.roles, indent=4, sort_keys=True)

	# filemgr.write_data_to_file("files.txt", filemgr.files)
	# filemgr.files = filemgr.read_data_from_file("files.txt")
	# print "FILES: %s" % json.dumps(filemgr.files, indent=4, sort_keys=True)

	loop = 1
	state = "init"
	options = {
		"init": "1: Login as Root\n 2: Login as User\n 3: Show all Users\n 4: Show all Roles\n 5: Save\n 6: Save & Exit",
		"root": "1: Create User\n 2: Create Role\n 3: Add User to Role\n 4: Logout",
		"user": "1: Unlock Role\n 2: Lock Role \n 3: View assigned Roles\n 4: View users of Role\n 5: Create new file\n 6: Read file\n 7: Add Role to File\n 8: Logout"
	}
	active_user = None
	unlocked_roles = {}
	unlocked_roles_list = "None"

	while loop == 1:
		try:
			print "\n=================================="
			if   state == "root": print "Logged In as root user."
			elif state == "user": print "Logged In as: %s" % active_user
			else:  print "File Manager 1.0"

			if state == "user": print "Unlocked Roles: %s" % unlocked_roles_list

			print "\nOPTIONS:\n %s\n" % options[state]
			prompt = '> '
			print "Select option: "
			selection = raw_input(prompt)
			print("Selection: %s" % selection)

			selection = int(selection)
			if state == "init":
				if selection == 1:
					print "\nLogging in as Root"
					password_string = "\nPassword: "
					password = raw_input(password_string)
					if(filemgr.login("root", password)):
						# If pass
						active_user = "root"
						state = "root"
						print "Successfully logged in as '%s'." % active_user
					else:
						print "Failed to validate login."
				elif selection == 2:
					print "\nLogin as User"
					username = raw_input("\nUsername: ")
					password = raw_input("Password: ")
					if(filemgr.login(username, password)):
						password = None
						# If pass
						active_user = username
						state = "user"
						print "Successfully logged in as '%s'." % active_user
					else:
						print "Failed to validate login."
				elif selection == 3:
					print "\nShow all Users"
					print "\nUsers: %s" % ', '.join(filemgr.users.keys())
				elif selection == 4:
					print "\nShow all Roles"
					print "\nRoles: %s" % ', '.join(filemgr.roles.keys())
				elif selection == 5:
					print("\nSaving changes\n");
					filemgr.write_data_to_file("users.txt", filemgr.users)
					filemgr.write_data_to_file("roles.txt", filemgr.roles)
					filemgr.write_data_to_file("files.txt", filemgr.files)
				elif selection == 6:
					print("\nSaving changes and exiting\n");
					filemgr.write_data_to_file("users.txt", filemgr.users)
					filemgr.write_data_to_file("roles.txt", filemgr.roles)
					filemgr.write_data_to_file("files.txt", filemgr.files)
					exit()

			elif state == "root":
				if selection == 1:
					print "\nCreate User"
					username = raw_input("\nUsername: ")
					password = raw_input("Password: ")
					if(filemgr.create_user(username, password)):
						password = None
						print "Successfully created user."	
						if debug: print "Users: %s\n" % json.dumps(filemgr.users, indent=4, sort_keys=True)
					else:
						print "Failed to create user."	
				elif selection == 2:
					print "\nCreate Role"
					role_name = raw_input("\nRole Name: ")
					if(filemgr.create_role(role_name)):
						print "Successflly created role."	
						if debug: print "Roles: %s\n" % json.dumps(filemgr.roles, indent=4, sort_keys=True)
					else:
						print "Failed to create role."	
				elif selection == 3:
					print "\nAdd User to Role"
					root_password  = raw_input("\nRoot password: ")
					username  = raw_input("\nUsername: ")
					password  = raw_input("Password: ")
					role_name = raw_input("Role Name: ")
					if(filemgr.add_user_to_role(active_user, root_password, username, password, role_name)):
						password = None
						print "Successflly added user to role."	
						if debug: print "Users: %s\n" % json.dumps(filemgr.users, indent=4, sort_keys=True)
						if debug: print "Roles: %s\n" % json.dumps(filemgr.roles, indent=4, sort_keys=True)
					else:
						print "Failed to add user to role."	
				elif selection == 4:
					active_user = None
					print("\nLogging out");
					state = "init"

			elif state == "user":
				if selection == 1:
					print "\nUnlock Role"
					role_name = raw_input("Name of Role to unlock: ")
					password = raw_input("Please re-enter password: ")
					role = filemgr.unlock_role(active_user, password, role_name)
					password = None
					if(role):
						unlocked_roles[role_name] = role
						unlocked_roles_list = ', '.join(unlocked_roles.keys())
						print "\nSuccessfully unlocked role."	
					else:
						print "\nUser %s does not have access to %s role." % (active_user, role_name)	
				elif selection == 2:
					print "\nLock Role"
					role_name = raw_input("Name of Role to lock: ")
					if role_name in unlocked_roles.keys():
						unlocked_roles.pop(role_name)
						if len(unlocked_roles.keys()) > 0:
							unlocked_roles_list = ', '.join(unlocked_roles.keys())
						else: 
							unlocked_roles_list = "None"
					else:
						print "Specified role is not unlocked."
				elif selection == 3:
					print "\nView assigned Roles"
					password = raw_input("Please re-enter password: ")
					roles = filemgr.get_user_roles(active_user, password)
					password = None
					print "\nRoles: %s" % ', '.join(roles)
				elif selection == 4:
					print "\nView users of Role"
					role_name = raw_input("Role Name: ")
					if role_name in unlocked_roles:
						print "\nRole Users: %s" % ', '.join(unlocked_roles[role_name]['users'])
					else:
						print "Please unlock role '%s' to access role details." % role_name
				elif selection == 5:
					print "\nCreate new file"
					role_name  = raw_input("Role to associate with filename: ")
					filename   = raw_input("Filename: ")
					data       = raw_input("File Content: ")

					# Verify Role is unlocked
					if role_name in unlocked_roles:
						print "Role Users: %s" % ', '.join(unlocked_roles[role_name])
					else:
						print "\nPlease unlock role '%s' to access create a new file." % role_name
						continue

					role_public_key = unlocked_roles[role_name]['key']
					if(filemgr.create_file(filename, role_name, role_public_key, data)):
						print "\nSuccessflly created file."	
						if debug: print "Files: %s\n" % json.dumps(filemgr.files, indent=4, sort_keys=True)
					else:
						print "Failed to create file."	
				elif selection == 6:
					print "\nRead file"
					password   = raw_input("Password: ")
					filename   = raw_input("Filename: ")
					if filename not in filemgr.files.keys():
						print "Specified file not found."
						continue
					if debug: print filemgr.files
					file_roles = filemgr.files[filename]['keys'].keys()
					role_name = None
					for role in file_roles:
						if role in unlocked_roles.keys():
							role_name = role
					if role_name:
						role_private_key = filemgr.get_role_private_key(active_user, password, role_name)
						content = filemgr.read_file(filename, role_name, role_private_key)
						print "File Content: \n%s\n" % content
					else:
						print "\nFailed to read file.\nNone of the roles associated with file %s have been unlocked." % filename

				elif selection == 7:
					print "\nAdd Role to File"
				elif selection == 8:
					# Clear active Users
					active_user = None
					# Clear unlocked roles
					unlocked_roles.clear()
					unlocked_roles_list = "None"
					print("\nLogging out");
					state = "init"

		except Exception as e:
			traceback.print_exc()
			print "Invalid input. Please select a valid option."
