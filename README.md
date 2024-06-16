# AES-TEST
I want more custom AES only ( DON'T CARE )
#
Support Mode ( AES )
* CRYPTOGRAPHY
  * ECB 1 ( UNKNOWN )
  * CBC 2
  * CFB 3
  * OFB 5
  * CTR 6 ( UNKNOWN )
  * OPENPGP 7
  * CCM 8
  * EAX 9 ( UNKNOWN )
  * SIV 10
  * GCM 11 ( UNKNOWN )
  * OCB 12
* PYCRYPTODOME
  * ECB 1 ( Working )
  * CBC 2
  * CTR 3 ( Working )
  * CFB 4
  * CFB8 5
  * OFB 6
  * GCM 7 ( Working )
  * XTS 8
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
