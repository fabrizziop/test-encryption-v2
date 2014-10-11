import hashlib
import binascii
import random
import time
import hmac
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

def generate_header_contents(f_len, password, ver, key_amount):
	header = []
	if key_amount > 65535 or len(ver) != 2:
		return "F"
	print('key amount:',key_amount)
	key_amount_str = format(key_amount, '02x')
	while len(key_amount_str) < 4:
		key_amount_str = "0" + key_amount_str
	header.append(key_amount_str)
	print(header)
	final_key_split = []
	for i in range(0,key_amount):
		cs = init_key_generation(512)
		print('salt:',cs)
		ck = init_key_generation(512)
		final_key_split.append(ck)
		#print(hashlib.pbkdf2_hmac('sha512', password.encode(), bytes.fromhex(cs), 10000))
		k_xor_mask = bytes.decode(binascii.hexlify(hashlib.pbkdf2_hmac('sha512', password.encode(), bytes.fromhex(cs), 500000)))
		ciphered_key = do_xor_on_hex(k_xor_mask,ck)
		header.append(cs)
		header.append(ciphered_key)
	print('version:',ver)
	print('length:',f_len)
	header.append(ver)
	header.append(f_len)
	hmac_salt = header[1]
	#print(hmac_salt)
	k_pbkdf_hmac = hashlib.pbkdf2_hmac('sha512', password.encode(), bytes.fromhex(hmac_salt), 500000)
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
	print('key amount:',key_amount)
	hmac_in_hdr = header_str[-128:]
	#print(header_str[4:132])
	k_pbkdf_hmac = hashlib.pbkdf2_hmac('sha512', password.encode(), bytes.fromhex(header_str[4:132]), 500000)
	hmac_val = hmac.new(k_pbkdf_hmac, header_str[:-128].encode(), hashlib.sha512).hexdigest()
	if hmac_in_hdr == hmac_val:
		hmac_validated = True
	else:
		hmac_validated = False
	print('read hmac:',hmac_in_hdr)
	print('calculated hmac:', hmac_val)
	final_key = []
	for i in range(0,key_amount):
		cs = header_str[(i*256)+4:(i*256)+132]
		print('salt:',cs)
		ck = header_str[(i*256)+132:(i*256)+260]
		#print(hashlib.pbkdf2_hmac('sha512', password.encode(), bytes.fromhex(cs), 10000))
		k_xor_mask = bytes.decode(binascii.hexlify(hashlib.pbkdf2_hmac('sha512', password.encode(), bytes.fromhex(cs), 500000)))
		deciphered_key = do_xor_on_hex(k_xor_mask,ck)
		final_key.append(deciphered_key)
	ver = header_str[(key_amount*256)+4:(key_amount*256)+6]
	length = header_str[(key_amount*256)+6:-128]
	print('version:',ver)
	print('length:',length)
	fk = "".join(final_key)
	print('key:', fk)
	return fk, ver, length, hmac_validated
	
	
class sha512_nfb(object):
	def __init__(self, init_key):
		self.current_state = hashlib.sha512(bytes.fromhex(init_key)).digest()
	def get_output(self):
		initk = self.current_state
		self.current_state = hashlib.sha512(initk).digest()
		return hashlib.sha512(bytes.fromhex(hex_transpose(bytes.decode(binascii.hexlify(initk))))).hexdigest() 
		
class sha512_efb(object):
	def __init__(self, init_key):
		self.current_key = bytearray.fromhex(init_key)
		self.current_feedback = bytearray(hashlib.sha512(self.current_key).digest())
	def get_bytes_to_xor(self):
		self.current_key = self.current_key[-1:]+self.current_key[:-1]
		self.current_thing_to_hash = self.current_key+self.current_feedback
		self.current_feedback = bytearray(hashlib.sha512(self.current_thing_to_hash).digest())
		self.current_output_bytes = bytearray(hashlib.sha512(byte_transpose(self.current_thing_to_hash)).digest())
		return self.current_output_bytes

class sha512_efb_pfb(object):
	def __init__(self, init_key):
		self.current_key = bytearray.fromhex(init_key)
		self.current_feedback = bytearray(hashlib.sha512(self.current_key).digest())
	def get_bytes_to_xor(self,ptxthash):
		self.current_key = self.current_key[-1:]+self.current_key[:-1]
		self.current_thing_to_hash = self.current_key+self.current_feedback+ptxthash
		self.current_feedback = bytearray(hashlib.sha512(self.current_thing_to_hash).digest())
		self.current_output_bytes = bytearray(hashlib.sha512(byte_transpose(self.current_thing_to_hash)).digest())
		return self.current_output_bytes
		
def encrypt_file(filename,passtouse,ver,key_par):
	ftoe = open(filename,'rb')
	ftoe_r = bytearray(ftoe.read())
	ftoe_r_l = len(ftoe_r)
	print(len(ftoe_r))
	timestopad = 64-(ftoe_r_l%64)
	for i in range(0,timestopad):
		ftoe_r.append(rng.randint(0,255))
	f_hash = hashlib.sha512(ftoe_r[0:ftoe_r_l]).digest()
	ftoe_r.extend(f_hash)
	print(len(ftoe_r))
	headercontent, tkey = generate_header_contents(format(ftoe_r_l, '02x'),passtouse,ver,key_par)
	nfname = filename + '.header'
	nfname_e = filename + '.crypto'
	hfi = open(nfname,'w')
	hfi.write(headercontent)
	hfi.close()
	hfi = open(nfname,'r')
	tkey2,_,_, hmac_s= read_header_contents(hfi.read(),passtouse)
	hfi.close()
	if tkey == tkey2 and hmac_s == True:
		print('Header file created, written and validated')
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
	fout = open(nfname_e,'wb')
	fout.write(enc_file)
	fout.close()
	#print('wk:',tkey)
	#print('rk:',tkey2)
	print('time: ', str(time.time()-time_st))
	
def decrypt_file(filename,passtouse):
	nfname = filename + '.header'
	nfname_e = filename + '.crypto'
	hfile = open(nfname,'r')
	key,ver,hlen,val = read_header_contents(hfile.read(),passtouse)
	length = int(hlen,16)
	if val == False:
		print('Wrong password, or corrupted/tampered header')
		x = input('Press Y to continue, other key to quit ')
		if (x != 'Y') and (x != 'y'):
			return "F"
	else:
		print('Header read and OK')
	efile = open(nfname_e,'rb')
	efile_r = efile.read()
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
	if fcalc_hash == d_file[-64:]:
		print('File OK')
	else:
		print('File has been tampered or corrupted')
		x = input('Press Y to continue, other key to quit ')
		if (x != 'Y') and (x != 'y'):
			return "F"
	print('time: ', str(time.time()-time_st))
	outf = open(filename,'wb')
	outf.write(d_file)
	outf.close()
	
def change_password(filename,password_old,password_new):
	nfname = filename + '.header'
	nf = open(nfname,'r')
	header_str = nf.read()
	nf.close()
	key_amount = int(header_str[0:4],16)
	hmac_in_hdr = header_str[-128:]
	k_pbkdf_hmac = hashlib.pbkdf2_hmac('sha512', password_old.encode(), bytes.fromhex(header_str[4:132]), 500000)
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
	new_header.append(header_str[0:4])
	for i in range(0,key_amount):
		cs = header_str[(i*256)+4:(i*256)+132]
		ck = header_str[(i*256)+132:(i*256)+260]
		k_xor_mask_d = bytes.decode(binascii.hexlify(hashlib.pbkdf2_hmac('sha512', password_old.encode(), bytes.fromhex(cs), 500000)))
		deciphered_key = do_xor_on_hex(k_xor_mask_d,ck)
		k_xor_mask_e = bytes.decode(binascii.hexlify(hashlib.pbkdf2_hmac('sha512', password_new.encode(), bytes.fromhex(cs), 500000)))
		reciphered_key = do_xor_on_hex(k_xor_mask_e,deciphered_key)
		new_header.append(cs)
		new_header.append(reciphered_key)
	ver = header_str[(key_amount*256)+4:(key_amount*256)+6]
	length = header_str[(key_amount*256)+6:-128]
	new_header.append(ver)
	new_header.append(length)
	f_header = "".join(new_header)
	k_pbkdf_hmac_n = hashlib.pbkdf2_hmac('sha512', password_new.encode(), bytes.fromhex(f_header[4:132]), 500000)
	hmac_val_n = hmac.new(k_pbkdf_hmac_n, f_header.encode(), hashlib.sha512).hexdigest()
	nh = []
	nh.append(f_header)
	nh.append(hmac_val_n)
	finalr_head = "".join(nh)
	finalf = open(nfname,'w')
	finalf.write(finalr_head)
	finalf.close()
	print('Done!')
# k2 = init_key_generation(512)
# k3 = binascii.hexlify(binascii.unhexlify(k2))
# print(k3)
# print(bytes.decode(k3))
# print(bytes.decode(binascii.unhexlify(k2)))
# size = int(input("Enter file size in MB"))
# rs = size * 16384
# cs = 0
# nf = open("rngtest2.bin","wb")
# while cs < rs:
	# if cs % 327680 == 0:
		# print(str(cs//16384)+"MB")
	# nf.write(binascii.unhexlify(k1.get_output()))
	# cs += 1
# nf.close()

f = open("testheader.txt",'w')
# file_length = format(int(input('length')), '02x')
# version = format(int(input('version')), '02x')
# k_am = int(input('key amount'))
# password = str(input('password'))

# file_length = format(1321315234631,'02x')
#version = '01'
#k_am = 1
# password = 'SAFW324cs'
# temp = generate_header_contents(file_length, password, version, k_am)
# f.write(temp)
# f.close()
# test_key =read_header_contents(temp, password)
# testc = sha512_efb(test_key)
# print()
# print(binascii.hexlify(testc.current_key))
# print(binascii.hexlify(testc.current_feedback))
# for i in range(1,20):
	# print(binascii.hexlify(testc.get_bytes_to_xor()))
	# print('key:',binascii.hexlify(testc.current_key))
	#print('feed:',binascii.hexlify(testc.current_feedback))
	
print('Encryption Test v2 r1.0')
print('By fabrizziop')
print('MIT licence')
ed = int(input('1: Encrypt, 2: Decrypt, 3: Change Password '))
if ed == 1:
	fname = input('File name to encrypt: ')
	k_am = int(input('Key length = 512 * '))
	passw = input('Password: ')
	ver = int(input('Version: '))
	if ver == 1:
		version = '01'
	elif ver == 2:
		version = '02'
	encrypt_file(fname,passw,version,k_am)
elif ed == 2:
	fname = input('File name to decrypt: ')
	passw = input('Password: ')
	decrypt_file(fname,passw)
elif ed == 3:
	fname = input('File name to change password: ')
	passw = input('Old Password: ')
	passwn = input('New Password: ')
	change_password(fname, passw, passwn)

# k1 = init_key_generation(512)
# print(k1)
# print(hex_transpose(k1))
# k1b = bytes.fromhex(k1)
# print(k1b)
# k1bt = byte_transpose(k1b)
# print(k1bt)
# k1btt = byte_transpose(k1bt)
# print(bytes.decode(binascii.hexlify(k1bt)))
# print(bytes.decode(binascii.hexlify(k1btt)))

# k2 = init_key_generation(512)
# xor_hex = do_xor_on_hex(k1,k2)
# print(xor_hex)
# k3 = bytes.fromhex(k1)
# k4 = bytes.fromhex(k2)
# xor_bytes = do_xor_on_bytes(k3,k4)
# print(binascii.hexlify(xor_bytes))
# print(xor_bytes)

#print(k1.current_state)
