# Task1-2_Cryptography_NT219.O11.ANTN
Task 1: Coding DES, AES using cryptopp library

A. Required:

+) Mode of operations:
  - Select mode from screen (using switch case)
  - Support modes:  ECB, CBC, OFB, CFB, CTR, XTS, CCM, GCM.
+) separate encryption function from decryption function:

   Select from screen (using switch case)
+) inputs:
  - Secret key,  Initialization Vector IV, and nonce,..
  - Select from screen (using switch case)
  Case 1: Secret key and IV are randomly chosen for each run time using random generator using CryptoPP::AutoSeededRandomPool;
  
  Case 2: Input Secret Key and IV from screen
  
  Case 3: Input Secret Key and IV from file (using file name)
 - Plaintext

    Case 1: Input from screen;
   
    Case 2: From files (using file name);
 - Support Vietnamse (using setmode, UTF-16)
 - Ciphertext

    Case 1: Input from screen;
   
    Case 2: From files (using file name);
    - Support Vietnamse (using setmode, UTF-16)
  
+) Ouputs (hex or base64 encode, binary):

   - display in screen;
  
   - write to file;

Task 2: Coding AES using only C++ without other cryptographic external libraries;

Required:

+) Plaintext: 

- Input from screen;
- Support Vietnamese (using _setmode, UTF-16)
  
+) Mode of operations

Using CBC mode

+) Secret key and Initialization Vector (IV)

Input Secret Key and IV from screen

Note for task 1, task 2 inmplemetation in order
1. modes?
2. encryption or decryption?
3. inputs?
4. ouputs?
# Comparision running time in task1 between Windows and Ubuntu
![image](https://github.com/tvdat20004/Task1-2_Cryptography_NT219.O11.ANTN/assets/117071011/a6f72646-996f-4ffe-85ff-f77ef4c17441)

![image](https://github.com/tvdat20004/Task1-2_Cryptography_NT219.O11.ANTN/assets/117071011/bf93fb37-b9cc-4d2c-9f15-665a0b03f847)

