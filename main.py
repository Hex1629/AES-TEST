from Crypto.Cipher import AES,PKCS1_OAEP,Salsa20
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import random, string, hashlib,base64,os
from hashlib import pbkdf2_hmac
import os

class CREATE_STRING():
  
  def generate_string(lengths):
   try:
     return [''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=length)) for length in lengths]
   except:return ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=lengths))

class RSA_TEST():
  def __init__(self, length=2048, public_key=None,private_key=None):
    if public_key == None and private_key == None:
     if length not in [1024,2048,3072,4096]:
       length = 1024
     key = RSA.generate(length)
     private_key = key.export_key()
     public_key = key.publickey().export_key()
    elif public_key != None and private_key != None:pass
    else:raise SyntaxError("Maybe not match key public and private")
    self.public_key = public_key
    self.private_key = private_key
    
  def export_public(self):
    return self.public_key
  
  def export_private(self):
    return self.private_key

  def encrypt(self,data):
    if not isinstance(data, bytes):
      data = data.encode()
    rsa_key = RSA.import_key(self.public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_aes_key = cipher_rsa.encrypt(data)
    return encrypted_aes_key

  def decrypt(self,data):
    rsa_key = RSA.import_key(self.private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    aes_key = cipher_rsa.decrypt(data)
    return aes_key

class AES_CRYPTO():
  def __init__(self, key=None,iv=None,mode_aes=None,mode_key_hash="SHA256".encode(),mode_iv_hash=False,mode_pad=2,secured_random_key='URANDOM'):
    """
    key for Key Must be string which will used to encrypt the strings or files
    iv for initializing vector which is used to randomize the encrypted data
    mode_aes for encrypting data
    mode_iv_hash for hashing iv with MD5 or default=False
    mode_key_hash for hashing key with SHA256,BLAKE2S,SHA3_256,PBKDF2-HMAC or default=False
    mode_pad for padded data for encryption ( 1,2 and 3 )
    secured_random_key for random bytes by URANDOM GETRANDOMBYTES"""
    if key == None:
       if secured_random_key == 'URANDOM':iv = os.urandom(32)
       elif secured_random_key == 'GETRANDOMBYTES':iv = get_random_bytes(32)
       else:key = CREATE_STRING.generate_string(32)
    if mode_aes != 12 and iv == None:
      if secured_random_key == 'URANDOM':iv = os.urandom(16)
      elif secured_random_key == 'GETRANDOMBYTES':iv = get_random_bytes(16)
      else:iv = CREATE_STRING.generate_string(16)
    else:
      iv = CREATE_STRING.generate_string(15)
    if mode_pad > 3:mode_pad = 2
    if mode_aes == None:mode_aes = 2
    mode_check = AES_METHODS.check_cryptomode(mode_aes)
    if mode_check != False:
      if AES_METHODS.check_iv(iv) == False and mode_aes != 12:raise SyntaxError(f"{iv}={len(iv)} must be length 16")
      if mode_key_hash == 'SHA256':key = hashlib.sha256(key.encode()).digest()
      elif mode_key_hash == 'BLAKE2S':key = hashlib.blake2s(key.encode()).digest()
      elif mode_key_hash == "PBKDF2-HMAC":key = hashlib.pbkdf2_hmac('sha256', key.encode(), os.urandom(16), 100000, dklen=32)
      elif mode_key_hash == 'None':key = key # FOR CURRENTLY NORMALY
      else:key = hashlib.sha3_256(key.encode()).digest()
      if mode_aes != 12 and mode_iv_hash == True:iv = hashlib.md5(iv.encode()).digest()
      else:iv = iv.encode()
      self.value = [key,iv,mode_check[0],mode_pad]
    else:
      raise SyntaxError(f"{mode_aes} not match in {mode_check}")
    
  def export(self):
    """
    For export key,iv,mode in list version
    """
    return self.value
  
  def encrypt(self, data):
    """
    data for Encrypt message"""
    if not isinstance(data, str):
      data = data.decode()
    self.bypass_data = data
    try:
      pad = self.value[3]
      if pad == 1:
       data = PAD.pad_data2(data)
      elif pad == 2:
       data = PAD.pad_data2(data)
      else:
        data = PAD.pad_data3(data.encode())
      if self.value[2] not in [10,11,12]:
       if self.value[2] == 1:
         return AES.new(self.value[0], self.value[2]).encrypt(data)
       else:
        return AES.new(self.value[0], self.value[2], self.value[1]).encrypt(data)
      else:
        cipher = AES.new(self.value[0], self.value[2], nonce=self.value[1])
        ciphertext, self.tag = cipher.encrypt_and_digest(data)
        return ciphertext
    except Exception as e:
      return e

  def decrypt(self, data, mode=None):
    """
    data for Decrypt message
    mode for Bypass decrypt with original message
    """
    try:
     if mode != None:
       return self.bypass_data
     else:
      if self.value[2] in [10,11,12]:
        cipher = AES.new(self.value[0], self.value[2], nonce=self.value[1])
        return cipher.decrypt_and_verify(data, self.tag).decode().rstrip()
      else:
       if self.value[2] == 1:
         data = AES.new(self.value[0],self. value[2]).decrypt(data).decode().rstrip()
       else:
         data = AES.new(self.value[0],self. value[2], self.value[1]).decrypt(data).decode().rstrip()
       if self.value[3] == 3:
         data = PAD.unpad(data.encode())
       return data
    except Exception as e:return e

class AES_CRYPTOGRAPHY():
  def __init__(self, key=None,iv=None,mode_aes=None,mode_key_hash="SHA256",auth_message=b"TH3ReAR3@uTHM_G!",secured_random_key='GETRANDOMBYTES'):
    if not isinstance(auth_message, bytes):
      auth_message = auth_message.encode()
    """
    key for Key Must be string which will used to encrypt the strings or files
    iv for initializing vector which is used to randomize the encrypted data
    mode_aes for encrypting data
    mode_key_hash for hashing key SHA256,BLAKE2S,SHA3_256,PBKDF2-HMAC
    auth_message for GCM ENCRYPTION
    secured_random_key for random bytes by URANDOM GETRANDOMBYTES"""
    if key == None:
       if secured_random_key == 'URANDOM':iv = os.urandom(32)
       elif secured_random_key == 'GETRANDOMBYTES':iv = get_random_bytes(32)
       else:key = CREATE_STRING.generate_string(32)
    if iv == None:
      if secured_random_key == 'URANDOM':iv = os.urandom(16)
      elif secured_random_key == 'GETRANDOMBYTES':iv = get_random_bytes(16)
      else:iv = CREATE_STRING.generate_string(16)
    if mode_aes == None:mode_aes = 2
    mode_check = AES_METHODS.check_cryptomode(mode_aes,type="CRYPTOGRAPHY")
    if mode_check != False:
      if AES_METHODS.check_iv(iv) == False:return f"{iv}={len(iv)} must be length 16"
      if mode_key_hash == 'SHA256':key = hashlib.sha256(key.encode()).digest()
      elif mode_key_hash == 'BLAKE2S':key = hashlib.blake2s(key.encode()).digest()
      elif mode_key_hash == "PBKDF2-HMAC":key = hashlib.pbkdf2_hmac('sha256', key.encode(), os.urandom(16), 100000, dklen=32)
      elif mode_key_hash == 'None':key = key # FOR CURRENTLY NORMALY
      else:key = hashlib.sha3_256(key.encode()).digest()
      if mode_aes == 1:
        mode = mode_check[0]()
      else:
        mode = mode_check[0](iv.encode())
      self.value = [key,iv,mode,str(mode_check[1])]
      if str(mode_check[1]) == "7":
        self.value.append(auth_message)
    else:
      raise SyntaxError(f"{mode_aes} not match in {mode_check[2]}")
    
  def export(self):
    """
    For export key,iv,mode in list version
    """
    return self.value
  
  def encrypt(self,plaintext):
    "plaintext for Encrypt Message"
    if not isinstance(plaintext, bytes):
      plaintext = plaintext.encode()
    self.bypass_data = plaintext
    encryptor = Cipher(algorithms.AES(self.value[0]), self.value[2], backend=default_backend()).encryptor()
    if self.value[3] == '7':
      encryptor.authenticate_additional_data(self.value[4])
    d = encryptor.update(PAD.pad_data(plaintext,algorithms.AES.block_size // 8)) + encryptor.finalize()
    if self.value[3] == '7': 
      self.value.append(encryptor.tag)
    return d
  
  def decrypt(self,ciphertext,mode=None):
    """ciphertext for Decrypt Message
    mode for Bypass decrypt message with original message"""
    if mode != None:
      return self.bypass_data
    else:
     modes = ''
     if not isinstance(ciphertext, bytes):
      ciphertext = ciphertext.encode()
     if str(self.value[3]) == "7":
       modes = AES_METHODS.check_cryptomode(7,type="CRYPTOGRAPHY")[0](self.value[1].encode(),self.value[5])
     else:modes = self.value[2]
     decryptor = Cipher(algorithms.AES(self.value[0]), modes, backend=default_backend()).decryptor()
     if self.value[3] == '7':
      decryptor.authenticate_additional_data(self.value[4])
     return PAD.unpad(decryptor.update(ciphertext) + decryptor.finalize())
  
class AES_METHODS():
  def check_cryptomode(mode,type=None):
    if type == "CRYPTOGRAPHY":
      modes_aes = {"1":modes.ECB,
  "2":modes.CBC,
  "3":modes.CTR,
  "4":modes.CFB,
  "5":modes.CFB8,
  "6":modes.OFB,
  "7":modes.GCM,
  "8":modes.XTS}
      try:
        return modes_aes[str(mode)],mode
      except:
        return False
    MODE_NAMES = {1: "ECB",2: "CBC",3: "CFB",5: "OFB",6: "CTR",9: "EAX",10: "SIV",11: "GCM",12: "OCB"}
    if isinstance(mode, int):
      NAME_MODE = MODE_NAMES.get(mode)
      if NAME_MODE != None:
       MODE_NUMBERS = {v: k for k, v in MODE_NAMES.items()}
       return int(MODE_NUMBERS[str(NAME_MODE)]),NAME_MODE,MODE_NAMES
      else:
       return False
    elif isinstance(mode, str):
     MODE_NUMBERS = {v: k for k, v in MODE_NAMES.items()}
     NAME_MODE = MODE_NUMBERS.get(mode)
     if NAME_MODE != None:
       return int(NAME_MODE),MODE_NAMES.get(NAME_MODE),MODE_NAMES
     else:
       return False
  
  def check_iv(iv):
    if len(iv) < 16 or len(iv) > 16:
      return False
    else:
      return True

class PAD():
  def pad_data(data, block_size):
        padder = padding.PKCS7(block_size * 8).padder()
        padded_data = padder.update(data) + padder.finalize()
        return padded_data

  def pad_data2(data):
        while len(data) % 16 != 0:data = data + ' '
        return data.encode()
  
  def pad_data3(data):
    padding_length = 16 - (len(data) % 16)
    padded_data = data + bytes([padding_length] * padding_length)
    return padded_data
  
  def unpad(data):
    padding_length = data[-1]
    unpadded_data = data[:-padding_length]
    return unpadded_data

class SALSA():
 def __init__(self, key=None,nonce=None):
    """
    Key The key is the secret value used to initialize the cipher.
    Nonce The nonce is a unique value used for each encryption to ensure the same plaintext doesn't result in the same ciphertext."""
    if key == None:key = get_random_bytes(32)
    if nonce == None:nonce = get_random_bytes(8)
    self.value = [key,nonce]
 
 def export(self):
   """
    For export key,nonce in list version
   """
   return self.value

 def encryption(self,plaintext=''):
  "plaintext for Encrypt Message"
  if not isinstance(plaintext, bytes):
    plaintext = plaintext.encode()
  self.plaintext = plaintext
  cipher = Salsa20.new(key=self.value[0], nonce=self.value[1])
  ciphertext = cipher.encrypt(plaintext)
  self.encode = ciphertext
  return ciphertext
  
 def decryption(self,ciphertext='',mode=0):
  """ciphertext for Decrypt Message
    mode for Bypass decrypt message with original message"""
  if mode == 0:
   if len(ciphertext) == 0:
    if not isinstance(ciphertext, bytes):
     ciphertext = ciphertext.encode()
   else:
     ciphertext = self.encode
   cipher = Salsa20.new(key=self.value[0], nonce=self.value[1])
   plaintext = cipher.decrypt(ciphertext)
  else:
    plaintext = self.plaintext
  return plaintext
