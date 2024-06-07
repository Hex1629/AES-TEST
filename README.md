# AES-TEST
I want more custom AES only ( DON'T CARE )
#
Support Mode ( AES )
* PYCRYPTODOME
  * ECB 1 ( Idk )
  * CBC 2
  * CFB 3
  * OFB 5
  * CTR 6 ( Idk )
  * OPENPGP 7
  * CCM 8
  * EAX 9 ( Idk )
  * SIV 10
  * GCM 11 ( Idk )
  * OCB 12
* CRYPTOGRAPHY
  * ECB 1 ( Working )
  * CBC 2
  * CTR 3 ( Working )
  * CFB
  * CFB8
  * OFB
  * GCM ( Idk )
  * XTS
# CODE

PYCRYPTODOME VERSION
 * ENCRYPT AND DECRYPT version Random Key, IV and Bypass Decrypt with Original message
   ```
   from main import *
   plain_text = "Hello, World"
   crypt = AES_CRYPTO(mode_aes=2)
   print(crypt.export())
   cipher_text = crypt.encrypt(plain_text)
   print(cipher_text)
   plain_text_decrypt = crypt.decrypt("1","1")
   print(plain_text_decrypt)
   ```
CRYPTOGRAPHY VERSION
 * ENCRYPT AND DECRYPT version Random Key, IV and Bypass Decrypt with Original message
 ```
   from main import *
   plain_text = "Hello, World"
   crypt = AES_CRYPTOGRAPHY(mode_aes=2)
   print(crypt.export())
   cipher_text = crypt.encrypt(plain_text)
   print(cipher_text)
   plain_text_decrypt = crypt.decrypt("1","1")
   print(plain_text_decrypt)
   ```
#
* Credit idea
  * https://pypi.org/project/Py-Encryptor/

* Requirement
  * https://pypi.org/project/cryptography/
  * https://pypi.org/project/pycryptodome/
