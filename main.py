from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import random, string, time, os
import hashlib
from cryptography.hazmat.primitives import padding

class CREATE_STRING():
  def generate_string(lengths):
   try:
     return [''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=length)) for length in lengths]
   except:return ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=lengths))

class AES_CRYPTO():
  def __init__(self, key=None,iv=None,mode_aes=None,mode_key_hash="SHA256".encode(),mode_iv_hash=False,mode_pad=2):
    """
    key for Key Must be string which will used to encrypt the strings or files
    iv for initializing vector which is used to randomize the encrypted data
    mode_aes for encrypting data
    mode_iv_hash for hashing iv with MD5 or default=False
    mode_key_hash for hashing key with SHA256,BLAKE2S,SHA3_256 or default=False
    mode_pad for padded data for encryption ( 1,2 and 3 )"""
    if key == None:key = CREATE_STRING.generate_string(32)
    if iv == None:iv = CREATE_STRING.generate_string(16)
    if mode_pad > 3:mode_pad = 2
    if mode_aes == None:mode_aes = 2
    mode_check = AES_METHODS.check_cryptomode(mode_aes)
    if mode_check != False:
      if AES_METHODS.check_iv(iv) == False:return f"{iv}={len(iv)} must be length 16"
      if mode_key_hash == 'SHA256':key = hashlib.sha256(key.encode()).digest()
      elif mode_key_hash == 'BLAKE2S':key = hashlib.blake2s(key.encode()).digest()
      else:key = hashlib.sha3_256(key.encode()).digest()
      if mode_iv_hash == 'MD5':iv = hashlib.md5(iv.encode()).digest()
      else:iv = iv.encode()
      self.value = [key,iv,mode_check[0],mode_pad]
    else:
      raise SyntaxError(f"{mode_aes} not match in {mode_check[2]}")
    
  def get_list(self):
    """
    For get key,iv,mode in list version
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
      return AES.new(self.value[0], self.value[2], self.value[1]).encrypt(data)
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
      data = AES.new(self.value[0],self. value[2], self.value[1]).decrypt(data).decode().rstrip()
      if self.value[3] == 3:
        data = PAD.unpad(data.encode())
      return data
    except Exception as e:return e

class AES_CRYPTOGRAPHY():
  def __init__(self, key=None,iv=None,mode_aes=None,mode_key_hash="SHA256"):
    """
    key for Key Must be string which will used to encrypt the strings or files
    iv for initializing vector which is used to randomize the encrypted data
    mode_aes for encrypting data
    mode_key_hash for hashing key SHA256,BLAKE2S,SHA3_256"""
    if key == None:key = CREATE_STRING.generate_string(32)
    if iv == None:iv = CREATE_STRING.generate_string(16)
    if mode_aes == None:mode_aes = 2
    mode_check = AES_METHODS.check_cryptomode(mode_aes,type="CRYPTOGRAPHY")
    if mode_check != False:
      if AES_METHODS.check_iv(iv) == False:return f"{iv}={len(iv)} must be length 16"
      if mode_aes == 1:
        mode = mode_check[0]()
      else:
        mode = mode_check[0](iv.encode())
      if mode_key_hash == 'SHA256':key = hashlib.sha256(key.encode()).digest()
      elif mode_key_hash == 'BLAKE2S':key = hashlib.blake2s(key.encode()).digest()
      else:key = hashlib.sha3_256(key.encode()).digest()
      self.value = [key,iv,mode]
    else:
      raise SyntaxError(f"{mode_aes} not match in {mode_check[2]}")
    
  def get_list(self):
    """
    For get key,iv,mode in list version
    """
    return self.value
  
  def encrypt(self,plaintext):
    "plaintext for Encrypt Message"
    if not isinstance(plaintext, bytes):
      plaintext = plaintext.encode()
    self.bypass_data = plaintext
    encryptor = Cipher(algorithms.AES(self.value[0]), self.value[2], backend=default_backend()).encryptor()
    return encryptor.update(PAD.pad_data(plaintext,algorithms.AES.block_size // 8)) + encryptor.finalize()
  
  def decrypt(self,ciphertext,mode=None):
    """ciphertext for Decrypt Message
    mode for Bypass decrypt message with original message"""
    if mode != None:
      return self.bypass_data
    else:
     if not isinstance(ciphertext, bytes):
      ciphertext = ciphertext.encode()
     decryptor = Cipher(algorithms.AES(self.value[0]), self.value[2], backend=default_backend()).decryptor()
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
    MODE_NAMES = {1: "ECB",2: "CBC",3: "CFB",5: "OFB",6: "CTR",7: "OpenPGP",8: "CCM",9: "EAX",10: "SIV",11: "GCM",12: "OCB"}
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
