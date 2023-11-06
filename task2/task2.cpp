// #include <cstdlib>
// #include <ctime>
#include <iostream>
#include <string>
#include <vector>
// #include <array>
// #include <stdexcept>
#include <map>
#include <stdint.h>
#include <iomanip>
#include <sstream>
/* Set utf8 support for windows*/ 
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#include <windows.h>
#else
#endif
/* Convert string <--> utf8*/ 
#include <locale>
#include <codecvt>

using namespace std;
using  std::codecvt_utf8;
typedef vector<uint8_t> bytes;

#include "AES.h"
#include "modes.h"
#include "key_expansion.h"

int main(int argc, char* argv[])
{
    #ifdef __linux__
    std::locale::global(std::locale("C.UTF-8"));
    #endif
  
    #ifdef _WIN32
    // Set console code page to UTF-8 on Windows
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    #endif
    string key;
    
    cout << "Please enter your key: ";
    cin >> key;

    bytes key_bytes = str_to_bytes(key);
    modes aes_cbc = modes(key_bytes);
    while (true)
    {
        int aes;
        cout<<"Would you like to encrypt or decrypt message?\n"
        << "1. Encrypt\n"
        << "2. Decrypt\n"
        << "Please enter a number(1-2): ";
        cin >> aes;
        
        if (aes == 1)
        {
            string plain;
            cout << "Enter plaintext:";
            cin.ignore();
            getline(cin, plain); 
            bytes plain_bytes = str_to_bytes(plain);
            bytes cipher = aes_cbc.cbc_encrypt(plain_bytes);
            cout << "Encrypted data(hex): " << hex(cipher) << endl;
        }
        else if (aes == 2)
        {
            string cipherHex;
            cout << "Enter ciphertext(hex): ";
            cin >> cipherHex;
            bytes recovered = aes_cbc.cbc_decrypt(decode_hex(cipherHex));
            cout << "Decrypted data: " << bytes_to_str(recovered);
            return 0;
        }
        else 
        {
            cout << "Invalid options";
            return 0;
        }
    }
    return 0;
}
