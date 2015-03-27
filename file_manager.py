from cryptography.fernet import Fernet
import hashlib
import os
import json

class Users():
	salt = os.urandom(8)

	def __init__(self):
		self.users = {}
		self.roles = {}

	def create_user(self, username, password, role_name, role_key):
		user_data = {
			"salted_password": password,
			"roles":  {},
		}
		self.users[username] = user_data
		self.create_role(role_name, role_key)
		self.add_user_to_role(username, role_name, role_key)

	def add_user_to_role(self, username, role_name, role_key):
		# Add new role to user data
		self.users[username]["roles"][role_name] = role_key

		# Add new user to role data
		self.roles[role_name]['users'].append(username)

	def create_role(self, role_name, role_public_key):
		self.roles[role_name] = {}
		self.roles[role_name]['key'] = role_public_key
		self.roles[role_name]['users'] = []


class Role():

	def __init__(self, name, key):
		self.name = name   # Name
		self.key = key     # Public Key
		self.users = []    # Associated Users

	def add_file(self, file_name, file_key):
		self.files[file_name] = file_key

class File():
	def __init__(self, filename, key, data):
		self.filename = filename
		self.data = data
		self.key = key

	def open(self):
		pass

if __name__ == '__main__':

	myUsers = Users();
	myUsers.create_user("joe", "pass", "r1", "rk")
	print "Users: %s" % json.dumps(myUsers.users)
	print "Roles: %s" % json.dumps(myUsers.roles)

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

	print "\n==================================\n"
	key = Fernet.generate_key()
	cipher_suite = Fernet(key)
	cipher_text = cipher_suite.encrypt("A really secret message. Not for prying eyes.")
	print cipher_text
	plain_text = cipher_suite.decrypt(cipher_text)
	print plain_text