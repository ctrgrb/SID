# pip3 install pycryptodome
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import hashlib, os, readline, time, sqlite3, string

STOP_WORDS = ['The','the','A', 'a','An', 'an','In', 'in', '/']

def aes_encrypt(plaintext, key):
	padded_text = pad(plaintext, 16)
	cipher = AES.new(key, AES.MODE_ECB)
	ciphertext = cipher.encrypt(padded_text)
	return ciphertext

def aes_decrypt(ciphertext, key):
	cipher = AES.new(key, AES.MODE_ECB)
	padded_text = cipher.decrypt(ciphertext)
	plaintext = unpad(padded_text, 16)
	return plaintext

def hash(text, len):
	if len == 1:
		return hashlib.sha1(text.encode()).digest()
	if len == 2:
		return hashlib.sha256(text.encode()).digest()
	if len == 3:
		return hashlib.sha512(text.encode()).digest()

def clear_word(word):
	return word.translate(str.maketrans('','',string.punctuation))

def b64e(byte):
	return b64encode(byte).decode()

def b64d(string):
	return b64decode(string.encode())

### TA entity reperesented by a class
class TA:
	def __init__(self, K_TA):
		self.K_TA = K_TA

	def send_In_TA(self):
		# Send the database to the TA
		os.system('cp words.db TA/In_TA.db')

	def request_nofiles_nosearch(self, word):
		# Send back the values if word exists
		conn = sqlite3.connect('TA/In_TA.db')
		c = conn.cursor()
		c.execute('SELECT NoFile, NoSearch \
			FROM words WHERE word="'+word+'"')
		try:
			(nofiles, nosearch) = c.fetchall()[0]
			return nofiles, nosearch
		except:
			return None, None

	def send_ack(self, word):
		# No.Search[w_j] ++
		conn = sqlite3.connect('TA/In_TA.db')
		c = conn.cursor()
		c.execute('UPDATE words SET NoSearch=NoSearch+1 WHERE word = "'+word+'"')
		conn.commit()
		conn.close()

	def print_db(self):
		conn = sqlite3.connect('TA/In_TA.db')
		c = conn.execute("SELECT * from words")
		print("Dict:")
		for row in c:
		   print("word =", row[0])
		   print("Nofile =", row[1])
		   print("NoSearch =", row[2])
		   print()
		conn.close()

	def forward_K_NoFiles(self, K, NoFiles):
		# h(wj)||No.Search[w_j] = Dec(K_TA , K_w_j)
		[h, NoSearch] = aes_decrypt(K, self.K_TA).decode().split("||")
		# No.Search[w_j] = No.Search[w_j] + 1
		NoSearch = int(NoSearch) + 1
		# K'_w_j = Enc(K_TA , h(w_j)||No.Search[w_j])
		hp = (str(h)+"||"+str(NoSearch)).encode()
		Kp = aes_encrypt(hp, self.K_TA)
		Lta = []
		# for i = 1 to i = No.Files[w_j] do
		for i in range(1, NoFiles + 1):
			# addr_w_j = h(K'_w_j , i||0)
			addr = hash(str(Kp)+str(i)+"||"+'0',1)
			# L_TA = L_TA U { addr_w_j}
			Lta.append(addr)
		# Send L_TA to the CSP
		return Lta

	def send_FileNumber(self, FileNumber): 
		# Get data from database and delete it
		conn = sqlite3.connect('TA/In_TA.db')
		c = conn.cursor()
		c.execute('SELECT * FROM words')
		word_list = c.fetchall()
		conn.close()
		os.system("rm TA/In_TA.db ")

		# organise data into a dict
		words = {}
		for i in word_list:
			words[i[0]] = [i[1], i[2]]
		hash_to_word_map = {}
		for word in words.keys():
			hash_to_word_map[hash(word,1)] = word

		# for all h(w_ij) ∈ FileNumber do
		for i in FileNumber:
			# if No.Files[w_ij] > 1 then
			word = hash_to_word_map[i]
			# No.Files[w_ij] −−
			if FileNumber[i] > 0:
				words[word][0] -= 1
			else:
				# Delete No.Files[w_ij] and No.Search[w_ij]
				del words[word]

		conn = sqlite3.connect('TA/In_TA.db')
		c = conn.cursor()

		# Recreate database
		c.execute('''CREATE TABLE words
		             ([word] text PRIMARY KEY,
		              [NoFile] INTEGER,
		              [NoSearch] INTEGER)''')
		conn.commit()
		# Add data to database
		List_of_Tuples = []
		for i in words:
			List_of_Tuples.append((i,words[i][0],words[i][1]))
		c.executemany('INSERT INTO words (word, NoFile, NoSearch) \
			  		   VALUES (?, ?, ?)', List_of_Tuples);
		conn.commit()
		conn.close()

### CSP entity reperesented by a class
class CSP:

	def create_CSP_database(self):
		conn = sqlite3.connect('CSP/CSP.db')
		c = conn.cursor()

		# Create table
		c.execute('''CREATE TABLE Dict
		             ([addr] text PRIMARY KEY,
		              [encr_filename] text,
		              [value] text)''')
		conn.commit()
		conn.close()

	def send_AllMap_and_c(self, AllMap, C):
		# Try to rebuild database
		try:
			command = 'rm CSP/CSP.db'
			os.system(command)
			self.create_CSP_database()
		except:
			pass
		# Write encrypted file
		for element in C:
			with open("CSP/"+element[0],'wb') as file:
				file.write(element[1])

		# Add data to CSP database
		conn = sqlite3.connect('CSP/CSP.db')
		c = conn.cursor()
		List_of_Tuples = []
		for i in AllMap.keys():
			List_of_Tuples.append((b64e(i),b64e(AllMap[i][0]),b64e(AllMap[i][1])))
		c.executemany('INSERT INTO Dict (addr, encr_filename, value) \
				  	VALUES (?, ?, ?)', List_of_Tuples);
		conn.commit()
		conn.close()

	def retrun_AllMap(self):
		AllMap = {}
		conn = sqlite3.connect('CSP/CSP.db')
		c = conn.execute("SELECT * from Dict")
		for row in c:
			AllMap[b64d(row[0])] = [b64d(row[1]), b64d(row[2])]
		return AllMap

	def print_db(self):
		conn = sqlite3.connect('CSP/CSP.db')
		c = conn.execute("SELECT * from Dict")
		print("Dict:")
		for row in c:
		   print("addr =", b64d(row[0]))
		   print("encr_filename =", b64d(row[1]))
		   print("value =", b64d(row[2]))
		   print()
		conn.close()

	def send_search_token(self, search_token):
		# Forward (K_w_j , No.Files[w_j]) to TA
		Lta = Trusted_Authority.forward_K_NoFiles(search_token[0], 
												  search_token[1])
		Lu = search_token[2]
		# if L_u = L_TA then
		if Lu == Lta:
			conn = sqlite3.connect('CSP/CSP.db')
			c = conn.cursor()
			I = []
			# for i = 1 to i = No.Files[w_j] do 
			for i in range(1, search_token[1]+1):
				# c_id(f_i) = Dict[(h(K_w_j , i||0))]
				s = b64e(hash(str(search_token[0])+str(i)+"||"+'0',1))
				c.execute('SELECT * FROM Dict WHERE addr="'+s+'"')
				fetch = c.fetchall()
				(addr, encr_filename, value) = fetch[0]
				I.append(b64d(encr_filename))
				# Delete Dict[(h(K_w_j , i||0))]
				c.execute('DELETE FROM Dict WHERE addr="'+s+'"')
				# Add the new addresses as specified by L_u
				c.execute('INSERT INTO Dict (addr, encr_filename, value) \
			      		VALUES ("'+b64e(Lu[i-1])+'","'+encr_filename+'","'+value+'")');
				conn.commit()
			conn.close()
			# Send I w_j to the user and an acknowledgement to the Data Owner
			return I
		else:
			# Output ⊥
			return None

	def send_delete_token(self, filename):
		# CSP sends f_i back to u_i before deleting the entries.
		self.download_encr_file(filename)
		# Delete File
		command = "rm CSP/{}_encrypted".format(filename)
		os.system(command)

	def update_entries(self, delete_token):
		conn = sqlite3.connect('CSP/CSP.db')
		c = conn.cursor()
		# for j = 1 to j = #w_i ∈ f_i do
		for j in delete_token.keys():
			# if newaddr w_ij = 0 then
			if delete_token[j][0] == 0:
				# Delete addr_w_ij and val_w_ij
				c.execute('DELETE FROM Dict WHERE addr="'+b64e(j)+'"')
			else:
				# addr_w_ij = naddr_w_ij
				# val_w_ij = nval_w_ij
				ex='UPDATE Dict SET addr="{}", value="{}" WHERE addr="{}"'.format(b64e(delete_token[j][0]), b64e(delete_token[j][2]), b64e(j))
				c.execute(ex)
			conn.commit()
		conn.close()


	def download_encr_file(self, fname):
		# Simulate file download
		os.system('cp CSP/{}_encrypted {}_encrypted'.format(fname, fname))
				

def create_owner_database():
	conn = sqlite3.connect('words.db')
	c = conn.cursor()

	# Create table
	c.execute('''CREATE TABLE words
	             ([word] text PRIMARY KEY,
	              [NoFile] INTEGER,
	              [NoSearch] INTEGER)''')
	conn.commit()
	conn.close()

def SID_Keygen(password):
	K = hash(password,3)	# 64 bytes
	K_TA = K[:32]			# First 32 bytes
	K_SKE = K[32:]			# Last 32 bytes
	return K_TA, K_SKE

def SID_AddFile(filename, K_TA, K_SKE, all_words):
	Map = {}
	# Read file
	with open(filename,'r') as file:
		data = file.read()
		words_in_file = data.split()
		words_in_file = list(dict.fromkeys(words_in_file)) # remove duplicate words
		try: filename = filename.split("/")[1]
		except: pass
		# for all w_ij ∈ f_i do
		for word in words_in_file:
			# word formatting
			if word not in STOP_WORDS:
				word = clear_word(word)
				# No.Files[w i j ] ++
				if word not in all_words.keys():
					all_words[word] = [1,0]
				else:
					all_words[word][0] += 1
				# K_w_ij = Enc(K_TA , h(w_ij )||No.Search[w_ij ])
				h = (str(hash(word,1))+"||"+str(all_words[word][1])).encode()
				K = aes_encrypt(h, K_TA)
				# addr w_ij = h(K_w_ij , No.Files[w_ij]||0)
				addr = hash(str(K)+str(all_words[word][0])+"||"+'0',1)
				# val w_ij = Enc(K_SKE , id(f_i )||No.Files[w_ij ])
				encoded_str = (str(all_words[word][0])).encode()
				val = [aes_encrypt(filename.encode(), K_SKE), aes_encrypt(encoded_str, K_SKE)]
				# Map = Map U { addr_w_ij , val_w_ij }
				Map[addr] = val
		
		# c_i ← SKE.Enc(K_SKE , f_i)
		c_data = aes_encrypt(data.encode("utf-8"), K_SKE)	
		return c_data, Map, all_words

def SID_Search(search_word, K_TA, K_SKE):
	# Request the values No.Files[w_j] and No.Search[w_j] for a keyword w_j, from TA
	nofiles, nosearch = Trusted_Authority.request_nofiles_nosearch(search_word)
	if nofiles == None:
		print("[-] Word not found.")
		return False
	# K_w_j = Enc(K_TA , h(w_j)||No.Search[w_j])
	h = (str(hash(search_word,1))+"||"+str(nosearch)).encode()
	K = aes_encrypt(h, K_TA)
	# No.Search[w_j] ++
	nosearch += 1
	# K'_w_j = Enc(K_TA , h(w_j)||No.Search[w_j])
	h = (str(hash(search_word,1))+"||"+str(nosearch)).encode()
	Kp = aes_encrypt(h, K_TA)
	Lu = []
	# for i = 1 to i = No.Files[w_j] do
	for i in range(1, nofiles+1):
		# addr w_j = h(K'_w_j , i||0)
		addr = hash(str(Kp)+str(i)+"||"+'0',1)
		# L_u = L_u U {addr_w_j}
		Lu.append(addr)

	# Send τ_s(w_j) = (K_w_j , No.Files[w_j], L_u) to the CSP
	search_token = [K, nofiles, Lu]
	response = Cloud.send_search_token(search_token)
	if response == None:
		print("[X] Protocol broken!")
		return
	# Download the files containing the searched word and decrypt them
	Files = []
	for i in response:
		Files.append(aes_decrypt(i,K_SKE).decode())
	for fname in Files:
		Cloud.download_encr_file(fname)
		data = ''
		with open(fname+"_encrypted", 'rb') as encr_f:
			encr_data = encr_f.read()
			data = aes_decrypt(encr_data,K_SKE)
		with open(fname, 'wb') as file:
			file.write(data)
		print("[+] Word found in {}. File downloaded and decrypted.".format(fname))
	return True

def SID_Delete(data, all_words, K_TA, K_SKE):
	t0 = time.time()
	FileNumber = {}
	delete_token = {}
	words_in_file = []
	# get words form data
	for byte in data.split():
		words_in_file.append(byte.decode())
	words_in_file = list(dict.fromkeys(words_in_file)) # remove duplicate words
	# for all w_ij ∈ f_i do
	for word in words_in_file:
		if word not in STOP_WORDS:
			word = clear_word(word)
			# addr_w_ij = h(K_w_ij , No.files[w_i_j]||0)
			h = (str(hash(word,1))+"||"+str(all_words[word][0])).encode()
			K = aes_encrypt(h, K_TA)
			addr = hash(str(K)+str(all_words[word][0])+"||"+'0',1)
			# val w_ij = Enc(K_SKE , id(f_i), No.Files[w_ij])
			encoded_str = (str(all_words[word][0])).encode()
			val = aes_encrypt(encoded_str, K_SKE)
			# if No.Files[w_ij] > 1 then
			if all_words[word][0] > 1:
				# No.Files[w_ij]− −
				all_words[word][0] -= 1
				# naddr = h(K_w_ij , No.files[w_ij]||0)
				naddr = hash(str(K)+str(all_words[word][0])+"||"+'0',1)
				encoded_str = (str(all_words[word][0])).encode()
				# nval = Enc(K_SKE , id(f)||No.Files[w_ij])
				nval = aes_encrypt(encoded_str, K_SKE)
				# FileNumber = FileNumber U {h(w_ij) No.Files[w_ij]}
				FileNumber[hash(word,1)] = all_words[word][0]
			else:
				naddr = 0
				nval = 0
				# Delete No.Files[w_ij] and No.Search[w_ij]
				del all_words[word]
				FileNumber[hash(word,1)] = 0

			# τ_d(f)
			delete_token[addr] = [naddr, val, nval]
			
	# Send FileNumber to the TA
	Trusted_Authority.send_FileNumber(FileNumber)
	#Send τ_d(f_i) to the CSP
	Cloud.update_entries(delete_token)
	print("[*] Ellapsed time:", time.time() - t0, "seconds")
	return all_words

def update_words_db(all_words, prev_all_words_list):
	conn = sqlite3.connect('words.db')
	c = conn.cursor()
	new_all_words = all_words.keys()
	for word in new_all_words:
		# NoFile -= 1 for word
		if word in prev_all_words_list:
			ex='UPDATE words SET NoFile="{}" WHERE word="{}"'.format(all_words[word][0], word)
			c.execute(ex)
		# Add new word
		elif word not in prev_all_words_list:
			c.execute('INSERT INTO words (word, NoFile, NoSearch) \
			      		VALUES ("'+word+'","'+str(all_words[word][0])+'","'+str(all_words[word][1])+'")');
	conn.commit()
	conn.close()


def SID_Modify(fname, K_TA, K_SKE, all_words):
	# Run the Delete Algorithm for a file f_i
	# Download encrypted file
	Cloud.send_delete_token(fname)
	# Decrypt data in file
	data = ''
	with open(fname+"_encrypted", 'rb') as encr_f:
		encr_data = encr_f.read()
		data = aes_decrypt(encr_data,K_SKE)
	# Store a copy of the previous all words
	prev_all_words_list = all_words.copy().keys()
	# Run SID_Delete function
	all_words = SID_Delete(data, all_words, K_TA, K_SKE)
	# Remove encrypted file
	command = "rm {}_encrypted".format(fname)
	os.system(command)
	print("[*] File {} deleted.".format(fname))
	# Write decrypted data to new file
	with open(fname, 'wb') as file:
		file.write(data)

	# Modify f i
	command = "nano {}".format(fname)
	os.system(command)

	# Run the AddFile Algorithm with the modified f_i as input
	print('[*] Generating new indexes.')
	t0 = time.time()
	# Get AllMap values from Cloud database
	AllMap = Cloud.retrun_AllMap()
	# Add edited file
	c_data, Map, all_words = SID_AddFile(fname, K_TA, K_SKE, all_words)
	AllMap = {**AllMap, **Map}
	# Recreate CSP database
	Cloud.send_AllMap_and_c(AllMap, [[fname+"_encrypted", c_data]])
	# remove edited file
	command = "rm {}".format(fname)
	os.system(command)
	# update user database and send it to the TA
	update_words_db(all_words, prev_all_words_list)
	Trusted_Authority.send_In_TA()
	print("[*] Ellapsed time:", time.time() - t0, "seconds")
	return all_words


def main():
	global Cloud
	global Trusted_Authority

	Cloud = CSP()
	all_words = {}

	### Generate K_TA, K_SKE based on a security parameter (user password)
	#password = "password" 
	password = input("[!] Enter a password: ")
	K_TA, K_SKE = SID_Keygen(password)
	print("[+] Keys generated.")

	### Send K _TA to the TA
	Trusted_Authority = TA(K_TA)

	# The first time the script is ran it will generate the databases
	while True:
		firstime = input("[?] Is this the first time running the script? (y/n) ")
		if firstime == "y" or firstime == "Y":
			firstime = True
		elif firstime == "n" or firstime == "N":
			firstime = False
		else:
			print("[!] Invalid onption please choose y or n.")
			continue
		break

	if firstime:
		create_owner_database()
		#foldername = "D184MB" 
		foldername = input("[*] Enter folder name: ")
		filenames = [f for f in os.listdir(foldername) if f.endswith('.txt')]
		
		print('[*] Generating the indexes and adding files.')
		t0 = time.time()
		### SID_InGen
		c = []
		AllMap = {}
		for filename in filenames:
			# Run AddFile to generate c_i and Map_i
			c_data, Map, all_words = SID_AddFile(foldername+'/'+filename, K_TA, K_SKE, all_words)
			# c = c U c_fi
			c.append([filename+"_encrypted", c_data])
			# AllMap = [ { AllMap U Map_i } , c_id(f_i ) ]
			AllMap = {**AllMap, **Map}

		# Add data to database file
		conn = sqlite3.connect('words.db')
		cur = conn.cursor()
		List_of_Tuples = []
		for i in all_words:
			List_of_Tuples.append((i,all_words[i][0],all_words[i][1]))
		cur.executemany('INSERT INTO words (word, NoFile, NoSearch) \
			  		   VALUES (?, ?, ?)', List_of_Tuples);
		conn.commit()
		conn.close()
		print("[*] Ellapsed time:", time.time() - t0, "seconds")

		# Send In_TA to the TA. Since it is a copy of the local 
		# indexes it just sends them to the TA
		os.mkdir('TA')
		Trusted_Authority.send_In_TA()
		print("[+] Indexes outsourced to the TA.")

		# Send (AllMap, c) to the CSP
		os.mkdir('CSP')
		print('[*] Generating CSP database.')
		t0 = time.time()
		Cloud.create_CSP_database()
		Cloud.send_AllMap_and_c(AllMap, c)
		print("[*] Ellapsed time:", time.time() - t0, "seconds")
		print('[+] Data outsourced to the CSP.')

	# If the script has already been run: save the data from the 
	# databases to a Dict
	else:
		conn = sqlite3.connect('words.db')
		cur = conn.cursor()
		cur.execute('SELECT * FROM words')
		fetch = cur.fetchall()
		for i in range(len(fetch)):
			all_words[fetch[i][0]] = [fetch[i][1], fetch[i][2]]
		conn.close()


	print("\n[H] Enter s to search, d to delete or m to modify.")
	while True:
		#Trusted_Authority.print_db()
		#Cloud.print_db()
		#print(all_words)
		try:
			sid = input("[SID]@shell:~$ ")
			if sid == 's':
				### SID.Search
				search_word = input("Enter a word to search: ")
				t0 = time.time()
				if SID_Search(search_word, K_TA, K_SKE):
					# No.Search[w] ++
					conn = sqlite3.connect('words.db')
					c = conn.cursor()
					c.execute('UPDATE words SET NoSearch=NoSearch+1 WHERE word = "'+search_word+'"')
					conn.commit()
					conn.close()
					# Send an acknowledgement to the TA
					Trusted_Authority.send_ack(search_word)
				print("[*] Ellapsed time:", time.time() - t0, "seconds")
			elif sid == 'd':
				fname = input("Enter file to delete: ")
				# send a delete token τ_d(f_i) for the file f_i to the CSP.
				Cloud.send_delete_token(fname)
				# u_i decrypts the received file
				data = ''
				with open(fname+"_encrypted", 'rb') as encr_f:
					encr_data = encr_f.read()
					# extract every keyword w_i_j contained in f_i
					data = aes_decrypt(encr_data,K_SKE)
				# update the indexes accordingly
				all_words = SID_Delete(data, all_words, K_TA, K_SKE)
				command = "rm {}_encrypted".format(fname)
				os.system(command)
				print("[*] File {} deleted.".format(fname))
			elif sid == 'm':
				fname = input("Enter file to modify: ")
				all_words = SID_Modify(fname, K_TA, K_SKE, all_words)
			else:
				pass

		except KeyboardInterrupt:
			print()
			break

main()