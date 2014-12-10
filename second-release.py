import hashlib
import binascii
import random
import time
import ctypes
import hmac
import os
import getpass
rng = random.SystemRandom()

def init_key_generation(keylengthbits):
	if keylengthbits < 8:
		keylengthbits = 8
	elif keylengthbits % 8 != 0:
		keylengthbits += ( 8 - keylengthbits % 8)
	key = []
	iters = keylengthbits // 8
	for i in range(0,iters):
		key.append(format(rng.randint(0,255), '02x'))
	return "".join(key)
	
def do_xor_on_hex(str1,str2):
	l1 = len(str1)
	if l1 != len(str2) or l1 % 2 != 0:
		print("ERROR!")
		return "Error"
	xor = []
	for i in range(0,l1,2):
		xor.append(format(int(str1[i:i+2],16)^int(str2[i:i+2],16),"02x"))
	return "".join(xor)
	
def do_xor_on_bytes(bs1,bs2):
	l1 = len(bs1)
	if l1 != len(bs2):
		print("ERROR!")
		return "Error"
	xor = bytearray()
	for i in range(0,l1):
		xor.append(bs1[i] ^ bs2[i])
	return xor

def hex_transpose(hexstr):
	v1 = 0
	newhex = []
	hexlen = len(hexstr)
	for i in range(0,hexlen,2):
		newhex.append(hexstr[i+1] + hexstr[i])
	newhex2 = newhex[(hexlen//4):] + newhex[0:(hexlen//4)]
	#print(newhex2)
	return "".join(newhex2)
	
def byte_transpose(binarr):
	binarrlen = len(binarr)
	newbin = bytearray()
	for i in range(0,binarrlen,2):
		newbin.append(binarr[i+1])
		newbin.append(binarr[i])
	newbin2 = newbin[(binarrlen//2):] + newbin[:(binarrlen//2)]
	return newbin2

def generate_header_contents(f_len, password, ver, key_amount, pbkdf2_iterations):
	header = []
	if key_amount > 65535 or len(ver) != 2 or pbkdf2_iterations > 65535:
		return "F"
	print('key amount:',key_amount)
	key_amount_str = format(key_amount, '02x')
	pbkdf2_real_iters = pbkdf2_iterations * 1000
	pbkdf2_str = format(pbkdf2_iterations, '02x')
	while len(key_amount_str) < 4:
		key_amount_str = "0" + key_amount_str
	while len(pbkdf2_str) < 4:
		pbkdf2_str = "0" + pbkdf2_str
	header.append(key_amount_str)
	header.append(pbkdf2_str)
	print('pbkdf2 iters:',pbkdf2_real_iters)
	print(header)
	final_key_split = []
	for i in range(0,key_amount):
		cs = init_key_generation(512)
		print('salt:',cs)
		ck = init_key_generation(512)
		final_key_split.append(ck)
		#print(hashlib.pbkdf2_hmac('sha512', password.encode(), bytes.fromhex(cs), 10000))
		k_xor_mask = bytes.decode(binascii.hexlify(hashlib.pbkdf2_hmac('sha512', password.encode(), bytes.fromhex(cs), pbkdf2_real_iters)))
		ciphered_key = do_xor_on_hex(k_xor_mask,ck)
		header.append(cs)
		header.append(ciphered_key)
	print('version:',ver)
	print('length:',f_len)
	header.append(ver)
	header.append(f_len)
	hmac_salt = header[2]
	#print(hmac_salt)
	k_pbkdf_hmac = hashlib.pbkdf2_hmac('sha512', password.encode(), bytes.fromhex(hmac_salt), pbkdf2_real_iters)
	n_head = "".join(header)
	#print(n_head)
	hmac_val = hmac.new(k_pbkdf_hmac, n_head.encode(), hashlib.sha512).hexdigest()
	n_head_2 = []
	n_head_2.append(n_head)
	n_head_2.append(hmac_val)
	print('key:', "".join(final_key_split))
	return "".join(n_head_2), "".join(final_key_split)
	
def read_header_contents(header_str, password):
	key_amount = int(header_str[0:4],16)
	pbkdf2_iterations = int(header_str[4:8],16)
	pbkdf2_real_iters = pbkdf2_iterations * 1000
	print('key amount:',key_amount)
	print('pbkdf2 iters:',pbkdf2_real_iters)
	hmac_in_hdr = header_str[-128:]
	#print(header_str[4:132])
	k_pbkdf_hmac = hashlib.pbkdf2_hmac('sha512', password.encode(), bytes.fromhex(header_str[8:136]), pbkdf2_real_iters)
	hmac_val = hmac.new(k_pbkdf_hmac, header_str[:-128].encode(), hashlib.sha512).hexdigest()
	if hmac_in_hdr == hmac_val:
		hmac_validated = True
	else:
		hmac_validated = False
	print('read hmac:',hmac_in_hdr)
	print('calculated hmac:', hmac_val)
	final_key = []
	for i in range(0,key_amount):
		cs = header_str[(i*256)+8:(i*256)+136]
		print('salt:',cs)
		ck = header_str[(i*256)+136:(i*256)+264]
		#print(hashlib.pbkdf2_hmac('sha512', password.encode(), bytes.fromhex(cs), 10000))
		k_xor_mask = bytes.decode(binascii.hexlify(hashlib.pbkdf2_hmac('sha512', password.encode(), bytes.fromhex(cs), pbkdf2_real_iters)))
		deciphered_key = do_xor_on_hex(k_xor_mask,ck)
		final_key.append(deciphered_key)
	ver = header_str[(key_amount*256)+8:(key_amount*256)+10]
	length = header_str[(key_amount*256)+10:-128]
	print('version:',ver)
	print('length:',length)
	fk = "".join(final_key)
	print('key:', fk)
	return fk, ver, length, hmac_validated
	
	
# class sha512_nfb(object):
	# def __init__(self, init_key):
		# self.current_state = bytearray(hashlib.sha512(bytes.fromhex(init_key)).digest())
	# def get_output(self):
		# initk = self.current_state
		# self.current_state = bytearray(hashlib.sha512(initk).digest())
		# return bytearray(hashlib.sha512(byte_transpose(initk)).digest()) 
		
class sha512_efb(object):
	def __init__(self, init_key):
		self.current_key = bytearray.fromhex(init_key)
		self.current_feedback = bytearray(hashlib.sha512(self.current_key).digest())
	def get_bytes_to_xor(self):
		self.current_key = self.current_key[-1:]+self.current_key[:-1]
		self.current_thing_to_hash = self.current_feedback+self.current_key
		self.current_feedback = bytearray(hashlib.sha512(self.current_thing_to_hash).digest())
		self.current_output_bytes = bytearray(hashlib.sha512(byte_transpose(self.current_thing_to_hash)).digest())
		return self.current_output_bytes

class sha512_efb_pfb(object):
	def __init__(self, init_key):
		self.current_key = bytearray.fromhex(init_key)
		self.current_feedback = bytearray(hashlib.sha512(self.current_key).digest())
	def get_bytes_to_xor(self,ptxthash):
		self.current_key = self.current_key[-1:]+self.current_key[:-1]
		self.current_thing_to_hash = self.current_feedback+ptxthash+self.current_key
		self.current_feedback = bytearray(hashlib.sha512(self.current_thing_to_hash).digest())
		self.current_output_bytes = bytearray(hashlib.sha512(byte_transpose(self.current_thing_to_hash)).digest())
		return self.current_output_bytes
		

		
def encrypt_file(filename,passtouse,ver,key_par, iter_k):
	try:
		ftoe = open(filename,'rb')
		ftoe_r = bytearray(ftoe.read())
		ftoe.close()
	except FileNotFoundError:
		print('File to encrypt not found')
		time.sleep(3)
		return "F"
	nfname = filename + '.header'
	try:
		header_presence_test = open(nfname,'rb')
		header_present = True
		header_presence_test.close()
	except FileNotFoundError:
		header_present = False
	if header_present == True:
		print('Header detected for file',filename,)
		print('If the file is already encrypted, overwriting it')
		print('WILL MAKE YOUR FILE UNRECOVERABLE, unless you have a')
		print('header file backup')
		x = input('Press Y to continue, other key to quit ')
		if (x != 'Y') and (x != 'y'):
			return "F"
		else:
			print('Header overwritten at your request!')
	ftoe_r_l = len(ftoe_r)
	print(len(ftoe_r))
	timestopad = 64-(ftoe_r_l%64)
	for i in range(0,timestopad):
		ftoe_r.append(rng.randint(0,255))
	f_hash = hashlib.sha512(ftoe_r[0:ftoe_r_l]).digest()
	ftoe_r.extend(f_hash)
	print(len(ftoe_r))
	headercontent, tkey = generate_header_contents(format(ftoe_r_l, '02x'),passtouse,ver,key_par, iter_k)
	hfi = open(nfname,'w')
	hfi.write(headercontent)
	hfi.close()
	hfi = open(nfname,'r')
	tkey2,_,_, hmac_s= read_header_contents(hfi.read(),passtouse)
	hfi.close()
	if tkey == tkey2 and hmac_s == True:
		print('Header file created, written and validated')
	else:
		print('Header file malfunction')
		print('Data loss is possible if you continue')
		x = input('Press Y to continue, other key to quit ')
		if (x != 'Y') and (x != 'y'):
			return "F"
	ftoe_r_l = len(ftoe_r)
	enc_file = bytearray()
	timestoencrypt = ftoe_r_l // 64
	csc = max(1,int(timestoencrypt/100))
	time_st = time.time()
	if ver == '01':
		cipher_object = sha512_efb(tkey)
		for i in range(0,timestoencrypt):
			cc = ftoe_r[(i*64):(i*64)+64]
			cbx = cipher_object.get_bytes_to_xor()
			ce = do_xor_on_bytes(cc,cbx)
			enc_file.extend(ce)
			if i % csc == 0:
				print(str(int(round((i*100/timestoencrypt),0)))+'%')
	elif ver == '02':
		cipher_object = sha512_efb_pfb(tkey)
		iv = hashlib.sha512(bytes.fromhex(hex_transpose(tkey))).digest()
		cfb = iv
		for i in range(0,timestoencrypt):
			cc = ftoe_r[(i*64):(i*64)+64]
			cbx = cipher_object.get_bytes_to_xor(cfb)
			ce = do_xor_on_bytes(cc,cbx)
			cfb = hashlib.sha512(cc).digest()
			enc_file.extend(ce)
			if i % csc == 0:
				print(str(int(round((i*100/timestoencrypt),0)))+'%')
	fout = open(filename,'wb')
	fout.write(enc_file)
	fout.close()
	#print('wk:',tkey)
	#print('rk:',tkey2)
	print('time: ', str(time.time()-time_st))
	
def decrypt_file(filename,passtouse, test_decrypt):
	nfname = filename + '.header'
	try:
		efile = open(filename,'rb')
		efile_r = efile.read()
		efile.close()
	except FileNotFoundError:
		print('File to decrypt not found')
		time.sleep(3)
		return "Fail"
	try:
		hfile = open(nfname,'r')
		key,ver,hlen,val = read_header_contents(hfile.read(),passtouse)
		hfile.close()
	except FileNotFoundError:
		print("Header is missing!, if you don't have a")
		print("backup, then your file is LOST FOREVER")
		time.sleep(3)
		return "Fail"
	length = int(hlen,16)
	if val == False:
		print('Wrong password, or corrupted/tampered header')
		x = input('Press Y to continue, other key to quit ')
		if (x != 'Y') and (x != 'y'):
			return "Abort"
	else:
		print('Header read and OK')
	d_file = bytearray()
	timestodecrypt = len(efile_r) // 64
	csc = max(1,int(timestodecrypt/100))
	time_st = time.time()
	if ver == '01':
		cipher_object = sha512_efb(key)
		for i in range(0,timestodecrypt):
			ce = efile_r[(i*64):(i*64)+64]
			cbx = cipher_object.get_bytes_to_xor()
			cd = do_xor_on_bytes(ce,cbx)
			d_file.extend(cd)
			if i % csc == 0:
				print(str(int(round((i*100/timestodecrypt),0)))+'%')
	elif ver == '02':
		cipher_object = sha512_efb_pfb(key)
		iv = hashlib.sha512(bytes.fromhex(hex_transpose(key))).digest()
		cfb = iv
		for i in range(0,timestodecrypt):
			ce = efile_r[(i*64):(i*64)+64]
			cbx = cipher_object.get_bytes_to_xor(cfb)
			cd = do_xor_on_bytes(ce,cbx)
			cfb = hashlib.sha512(cd).digest()
			d_file.extend(cd)
			if i % csc == 0:
				print(str(int(round((i*100/timestodecrypt),0)))+'%')
	fcalc_hash = hashlib.sha512(d_file[0:length]).digest()
	print('time: ', str(time.time()-time_st))
	autoremove = True
	if test_decrypt == True:
		if fcalc_hash == d_file[-64:]:
			return "File integrity OK"
		else:
			return "File has been tampered or corrupted"
	if fcalc_hash == d_file[-64:]:
		print('File OK')
	else:
		autoremove = False
		print('File has been tampered or corrupted')
		x = input('Press Y to continue (header autodelete disabled), other key to quit')
		if (x != 'Y') and (x != 'y'):
			return "Abort"
	outf = open(filename,'wb')
	outf.write(d_file[0:length])
	outf.close()
	if autoremove == True:
		print('Header file autodeleted')
		os.remove(nfname)
	
def change_password(filename,password_old,password_new):
	nfname = filename + '.header'
	try:
		nf = open(nfname,'r')
		header_str = nf.read()
		nf.close()
	except FileNotFoundError:
		print("Header is missing!")
		time.sleep(3)
		return "F"
	key_amount = int(header_str[0:4],16)
	pbkdf2_iterations = int(header_str[4:8],16)
	pbkdf2_real_iters = pbkdf2_iterations * 1000
	hmac_in_hdr = header_str[-128:]
	k_pbkdf_hmac = hashlib.pbkdf2_hmac('sha512', password_old.encode(), bytes.fromhex(header_str[8:136]), pbkdf2_real_iters)
	hmac_val = hmac.new(k_pbkdf_hmac, header_str[:-128].encode(), hashlib.sha512).hexdigest()
	if hmac_in_hdr != hmac_val:
		hmac_validated = False
		print('Wrong password, or corrupted/tampered header')
		print('If you continue, damage could be irreversible')
		x = input('Press Y to continue, other key to quit ')
		if (x != 'Y') and (x != 'y'):
			return "F"
	else:
		hmac_validated = True
	print('read hmac:',hmac_in_hdr)
	print('calculated hmac:', hmac_val)
	new_header = []
	new_header.append(header_str[0:8])
	for i in range(0,key_amount):
		cs = header_str[(i*256)+8:(i*256)+136]
		ck = header_str[(i*256)+136:(i*256)+264]
		k_xor_mask_d = bytes.decode(binascii.hexlify(hashlib.pbkdf2_hmac('sha512', password_old.encode(), bytes.fromhex(cs), pbkdf2_real_iters)))
		deciphered_key = do_xor_on_hex(k_xor_mask_d,ck)
		k_xor_mask_e = bytes.decode(binascii.hexlify(hashlib.pbkdf2_hmac('sha512', password_new.encode(), bytes.fromhex(cs), pbkdf2_real_iters)))
		reciphered_key = do_xor_on_hex(k_xor_mask_e,deciphered_key)
		new_header.append(cs)
		new_header.append(reciphered_key)
	ver = header_str[(key_amount*256)+8:(key_amount*256)+10]
	length = header_str[(key_amount*256)+10:-128]
	new_header.append(ver)
	new_header.append(length)
	f_header = "".join(new_header)
	k_pbkdf_hmac_n = hashlib.pbkdf2_hmac('sha512', password_new.encode(), bytes.fromhex(f_header[8:136]), pbkdf2_real_iters)
	hmac_val_n = hmac.new(k_pbkdf_hmac_n, f_header.encode(), hashlib.sha512).hexdigest()
	nh = []
	nh.append(f_header)
	nh.append(hmac_val_n)
	finalr_head = "".join(nh)
	finalf = open(nfname,'w')
	finalf.write(finalr_head)
	finalf.close()
	print('Done!')
	
print('Encryption Test r2.0')
print('By fabrizziop')
print('MIT licence')
print('This is only for testing. Using a SHA-512-based CSPRNG')
ed = int(input('1: Encrypt, 2: Decrypt, 3: Change Password, 4: Check, 5: Help '))
if ed == 1:
	fname = input('File name to encrypt: ')
	e_p_t_flag = False
	try:
		e_p_t = open(fname, 'r')
		e_p_t_flag = True
		e_p_t.close()
	except FileNotFoundError:
		pass
	if e_p_t_flag == True:
		k_am = 1
		try:
			k_am = int(input('Key length (X > 0) = 512 * X: [1] '))
		except ValueError:
			pass
		k_am = max(1,k_am)
		pass_ok = False
		while pass_ok == False:
			passw = getpass.getpass('Password: ')
			passw_check = getpass.getpass('Confirm password: ')
			if passw == passw_check:
				pass_ok = True
			else:
				print("Passwords don't match, please retry.")
		print('1: SHA-512 with key rotation and hash chain feedback')
		print('2: SHA-512 with key rotation, hash chain and plaintext feedback')
		ver = 2
		try:
			ver = int(input('Version: [2] '))
		except ValueError:
			pass
		it_amount = 1000
		try:
			it_amount = int(input('PBKDF2 Iterations (X > 0) = 1000 * X: [1000] '))
		except ValueError:
			pass
		it_amount = max(1,it_amount)
		if ver == 1:
			version = '01'
		elif ver == 2:
			version = '02'
		encrypt_file(fname,passw,version,k_am, it_amount)
	else:
		print('File to encrypt not found.')
		time.sleep(3)
elif ed == 2:
	fname = input('File name to decrypt: ')
	passw = getpass.getpass('Password: ')
	decrypt_file(fname,passw, False)
elif ed == 3:
	fname = input('File name to change password: ')
	passw = getpass.getpass('Old Password: ')
	pass_ok = False
	while pass_ok == False:
		passwn = getpass.getpass('Password: ')
		passwn_check = getpass.getpass('Confirm password: ')
		if passwn == passwn_check:
			pass_ok = True
		else:
			print("Passwords don't match, please retry.")
	change_password(fname, passw, passwn)
elif ed == 4:
	fname = input('File name to check: ')
	have_pass = str(input('Authenticate & Verify with password? Y/N [N] '))
	p_flag = False
	found_header = False
	if have_pass.upper() == 'Y':
			passw = getpass.getpass('Password: ')
			p_flag = True
	nfname = fname + '.header'
	try:
		nf = open(nfname,'r')
		header_str = nf.read()
		nf.close()
		found_header = True
	except FileNotFoundError:
		print("Header is missing!")
		time.sleep(3)
	if found_header == True:
		key_amount = int(header_str[0:4],16)
		pbkdf2_iterations = int(header_str[4:8],16)
		pbkdf2_real_iters = pbkdf2_iterations * 1000
		ver = header_str[(key_amount*256)+8:(key_amount*256)+10]
		length = header_str[(key_amount*256)+10:-128]
		if p_flag == True:
				hmac_in_hdr = header_str[-128:]
				k_pbkdf_hmac = hashlib.pbkdf2_hmac('sha512', passw.encode(), bytes.fromhex(header_str[8:136]), pbkdf2_real_iters)
				hmac_val = hmac.new(k_pbkdf_hmac, header_str[:-128].encode(), hashlib.sha512).hexdigest()
				if hmac_in_hdr == hmac_val:
					print('The header is OK')
					print('The following data is authenticated')
				else:
					print('Wrong password or tampered header')
					print('The following data is unauthenticated')
		else:
			print('The following data is unauthenticated')
		print('Key size:', key_amount*512)
		print('PBKDF2 iterations:', pbkdf2_real_iters)
		print('Encryption Version:', ver)
		print('Encrypted file length (bytes):', int(length,16))
		if p_flag == True:
			want_to_try_decrypt = str(input('Verify file integrity? Y/N [N] '))
			if want_to_try_decrypt.upper() == 'Y':
				print(decrypt_file(fname, passw, True))
		else:
			time.sleep(3)
elif ed == 5:
	print('Max key length: 65535*512 = 33553920 bits')
	print('Sane values are from 512 to 2048 bits')
	print('Max PBKDF2 iterations: 1000*65535=65535000')
	print('Sane values are from 10000 to 2000000 iterations')
	time.sleep(20)
else:
	print('Invalid option')
