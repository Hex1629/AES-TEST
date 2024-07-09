# AES-TEST
I want more custom AES only ( DON'T CARE )
#
Support Mode ( AES )
* PYCRYPTODOME
  * CBC 2
  * CFB 3
  * OFB 5
  * CTR 6 ( current wait )
  * EAX 9
  * SIV 10
  * GCM 11
  * OCB 12
* CRYPTOGRAPHY
  * ECB 1
  * CBC 2
  * CTR 3
  * CFB 4
  * CFB8 5
  * OFB 6
  * GCM 7
  * XTS 8
# CODE

PYCRYPTODOME VERSION
 * AES
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
 * RSA
   ```
   test = RSA_TEST(length=1024)
   print(test.export_private())
   cipher = test.encrypt('hi')
   print(cipher)
   print(test.decrypt(cipher))
 * SALSA 20
   ```
   C = SALSA()
   print(C.export())
   A = C.encryption('hi')
   print(A)
   print(C.decryption(A))
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
