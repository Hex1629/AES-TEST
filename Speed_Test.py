from main import *

def test_encryption():
 for c in [2,3,5,7,8,10,11,12]:
  for d in [16,32,64,128,256,512,1024,2048,4096,8192,16384,32768,65536]:
   data = CREATE_STRING.generate_string(d)
   for a in [16,24,32]:
    start_time = time.time()
    key,iv = CREATE_STRING.generate_string([a,16])
    cipher_text = AES_CRYPTO(key,iv,c).encrypt(data)
    end_time = time.time()
    e = end_time - start_time
    start_time2 = time.time()
    AES_CRYPTO(key,iv,c).decrypt(cipher_text)
    end_time2 = time.time()
    e2 = end_time2 - start_time2
    print(f"MODE={c} Time taken --> {e} : {e2}")
print("""Encryption and Decryption Speed Test
MODE = 2,3,5,7,8,10,11,12
DATA = 16,...,65536
KEY 16,24,32
IV  16""")
input("Press Enter !")
test_encryption()
