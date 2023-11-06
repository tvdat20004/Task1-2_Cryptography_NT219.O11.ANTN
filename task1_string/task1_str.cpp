
#include "encrypt_str.h"
#include "decrypt_str.h"
#include <chrono>

void get_keyboard_key_iv(int mode)
{
    // Nhap key tu ban phim (dang hex)
    string keyHex;
    cout<<"Enter key (in hex):";
    cin >> keyHex;
    // cin.ignore();
    StringSource(keyHex, true, new HexDecoder(new ArraySink(key, sizeof(key))));
    if (mode != 1)
    {
        // nhap iv tu ban phim
        string ivHex;
        cout<<"Enter IV (in hex):";
        cin >> ivHex;
        // cin.ignore();
    
        // decode iv tu hex -> byte
        StringSource(ivHex, true, new HexDecoder(new ArraySink(iv, sizeof(iv))));
    }
}

void get_key_iv_from_file(string fileKey, string fileIV)
{
    // Reading key from file
    FileSource(fileKey.data(), true, new HexDecoder(new ArraySink(key, sizeof(key))));
    if (fileIV != "")
    {
        FileSource(fileIV.data(), true, new HexDecoder(new ArraySink(iv, sizeof(iv))));
    }
}

string getPlainFromFile(string filename)
{
    string file_data;
    FileSource(filename.data(), true, new StringSink(file_data));
    return file_data;
}

string enter(string kindOfText)
{
    int selection;
    string text;
    cout<< "How do you want to enter "<<kindOfText<< ":\n"
    <<"1.From keyboard\n"
    <<"2.From file\n"
    <<"Please enter a number (1-2):";
    cin >> selection;
    switch (selection)
    {
        case 1:
        {
            cout <<"Enter " << kindOfText<< ": ";
            cin.ignore();
            getline(cin, text);
            
            break;  
        }
        case 2:
        {
            string filename;
            cout<<"Enter filename: ";
            cin >> filename;
            text = getPlainFromFile(filename);
        }
        default:
            break;
    }
    return text;
}

void write2File(string text)
{
    string filename;
    cout << "Enter filename:";
    // cin.ignore();
    cin >> filename;
    StringSource(text, true, new FileSink(filename.data()));
    cout << "Complete writing to file " << filename << endl;
}

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
    while(true)
    {
        // chon mode
        int mode;
        cout <<"Choose your mode:\n"
        << "1.ECB, 2.CBC, 3.OFB, 4.CFB, 5.CTR, 6.XTS, 7.CCM, 8.GCM\n";
        cin >> mode;

        // Encrypt or decrypt 
        int select;
        cout << "Would you like to encrypt or decrypt message:\n"
            << "1. Generate key and iv ;\n"
            << "2. Encrypt;\n"
            << "3. Decrypt;\n"
            << "Please enter your number?\n";
        
        cin >> select;

        switch (select) 
        {
            case 1: // gen key va IV
            {
                int keygen;
                cout<<"How do you want to gen key:\n"
                << "1.Random\n"
                << "2.Input from screen\n"
                << "3.Input from file\n"
                << "Please enter a number (1-3):";
                cin >> keygen;
                switch (keygen)
                {
                    case 1: // random key va iv
                    {
                        //random key
                        AutoSeededRandomPool prng;
                        prng.GenerateBlock(key, sizeof(key));
                        string encodedKey;
                        StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encodedKey)));        
                        cout << "Generated Key: " << encodedKey << endl;
                        
                        //random IV
                        if (mode != 1) 
                        {
                            string encodedIV;
                            prng.GenerateBlock(iv, sizeof(iv));
                            StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encodedIV)));
                            
                            cout << "Generated IV: " << encodedIV << endl;
                        }
                        break;
                    }
                    case 2: // nhap key va iv tu ban phim (dang hex)
                    {
                        get_keyboard_key_iv(mode);
                        break;
                    }
                    case 3: // nhap key va iv tu file 
                    {
                        string filenameKey;
                        cout<<"Enter key file name:";
                        cin >> filenameKey;
                        if (mode != 1)
                        {
                            string filenameIV;
                            cout<<"Enter IV file name:";
                            cin >> filenameIV;
                            get_key_iv_from_file(filenameKey, filenameIV);
                            break;
                        }
                        else
                            get_key_iv_from_file(filenameKey, "");
                        break;
                    }
                    default:
                    {
                        cout<<"Invalid option";
                        return 0;
                    }
                }
                break;
            }
            case 2: // Encrypt du lieu
            {
                // Nhap plaintext
                string plaintext;
                plaintext = enter("plaintext"); 
                int display;
                cout<< "How do you want to display output:\n"
                << "1.Display in screen\n"
                << "2.Write on file\n"
                << "Please choose a number(1-2): ";
                cin >> display;
                switch (mode)
                {
                    case 1: // ECB encrypt
                    {
                        string cipher;
                        auto start = std::chrono::high_resolution_clock::now();
                        for (int i = 0; i < 1000; ++i) 
                        {
                            cipher = ECB_encrypt(plaintext); 
                        }
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 1000.0;
                        cout << "Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
                        string cipherb64 = b64encode(cipher);
                        if (display == 1)
                            cout<<"Ciphertext(base 64):" << cipherb64 << endl;
                        else if (display == 2)
                        {
                            write2File(cipherb64);
                        }
                        else
                        {
                            cout << "Invalid cipher";
                            return 0;
                        }
                        break;
                    }
                    case 2: // CBC encrypt
                    {
                        string cipher;
                        auto start = std::chrono::high_resolution_clock::now();
                        for (int i = 0; i < 1000; ++i) 
                        {
                            cipher = CBC_encrypt(plaintext); 
                        }
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 1000.0;
                        cout << "Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
                        string ciphertext = b64encode(cipher);
                        if (display == 1)
                            cout<<"Ciphertext(base 64):" << ciphertext << endl;
                        else if (display == 2)
                        {
                            write2File(ciphertext);
                        }
                        else
                        {
                            cout << "Invalid cipher";
                            return 0;
                        }
                        break;
                    }
                    case 3: // OFB encrypt
                    {
                        string cipher;
                        auto start = std::chrono::high_resolution_clock::now();
                        for (int i = 0; i < 1000; ++i) 
                        {
                            cipher = OFB_encrypt(plaintext); 
                        }
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 1000.0;
                        cout << "Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
                        string ciphertext = b64encode(cipher);
                        if (display == 1)
                            cout<<"Ciphertext(base 64):" << ciphertext << endl;
                        else if (display == 2)
                        {
                            write2File(ciphertext);
                        }
                        else
                        {
                            cout << "Invalid cipher";
                            return 0;
                        }
                        break;
                    }
                    case 4: // CFB encrypt
                    {
                        string cipher;
                        auto start = std::chrono::high_resolution_clock::now();
                        for (int i = 0; i < 1000; ++i) 
                        {
                            cipher = CFB_encrypt(plaintext); 
                        }
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 1000.0;
                        cout << "Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
                        string ciphertext = b64encode(cipher);
                        if (display == 1)
                            cout<<"Ciphertext(base 64):" << ciphertext << endl;
                        else if (display == 2)
                        {
                            write2File(ciphertext);
                        }
                        else
                        {
                            cout << "Invalid cipher";
                            return 0;
                        }
                        break;
                    }
                    case 5: // CTR encrypt
                    {
                        string cipher;
                        auto start = std::chrono::high_resolution_clock::now();
                        for (int i = 0; i < 1000; ++i) 
                        {
                            cipher = CTR_encrypt(plaintext); 
                        }
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 1000.0;
                        cout << "Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
                        string ciphertext = b64encode(cipher);
                        if (display == 1)
                            cout<<"Ciphertext(base 64):" << ciphertext << endl;
                        else if (display == 2)
                        {
                            write2File(ciphertext);
                        }
                        else
                        {
                            cout << "Invalid cipher";
                            return 0;
                        }
                        break;
                    }
                    case 6: // XTS encrypt
                    {
                        string cipher;
                        auto start = std::chrono::high_resolution_clock::now();
                        for (int i = 0; i < 1000; ++i) 
                        {
                            cipher = XTS_encrypt(plaintext); 
                        }
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 1000.0;
                        cout << "Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
                        string ciphertext = b64encode(cipher);
                        if (display == 1)
                            cout<<"Ciphertext(base 64):" << ciphertext << endl;
                        else if (display == 2)
                        {
                            write2File(ciphertext);
                        }
                        else
                        {
                            cout << "Invalid cipher";
                            return 0;
                        }
                        break;
                    }
                    case 7: // CCM encrypt
                    {       
                        string cipher;                 
                        auto start = std::chrono::high_resolution_clock::now();
                        CryptoPP::byte truncatedIV[13];
	                    memcpy(truncatedIV, iv, 13);
                        for (int i = 0; i < 1000; ++i) 
                        {
                            cipher = CCM_encrypt(plaintext, truncatedIV); 
                        }
                        string ciphertext = b64encode(cipher);
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 1000.0;
                        std::cout << "Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
                        if (display == 1)
                            cout << "Ciphertext base64 (enc + tag):" << ciphertext << endl;
                        else if (display == 2)
                        {
                            write2File(ciphertext);
                        }
                        else
                        {
                            cout << "Invalid cipher";
                            return 0;
                        }
                        break;
                        
                    }
                    case 8: // GCM encrypt
                    {
                        string AAD;
                        cout << "Enter Additional Authenticated Data(AAD): "; 
                        cin >> AAD;
                        
                        string cipher;
                        auto start = std::chrono::high_resolution_clock::now();
                        for (int i = 0; i < 1000; ++i) 
                        {
                            cipher = GCM_encrypt(plaintext, AAD); 
                        }
                        string ciphertext = b64encode(cipher);
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 1000.0;
                        std::cout << "Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
                        if (display == 1)
                            cout << "Ciphertext base64 (enc + tag):" << ciphertext << endl;
                        else if (display == 2)
                        {
                            write2File(ciphertext);
                        }
                        else
                        {
                            cout << "Invalid cipher";
                            return 0;
                        }
                        break;
                    }
                    default:
                    {
                        cout<<"Invalid option";
                        return 0;
                    }
                }
                break;
            }
            case 3: // Decrypt du lieu
            {
                // Nhap ciphertext
                string cipher = b64decode(enter("ciphertext(base 64)"));
                int display;
                cout<< "How do you want to display output:\n"
                << "1.Display in screen\n"
                << "2.Write on file\n"
                << "Please choose a number(1-2): ";
                cin >> display;
                switch (mode)
                {
                    case 1: // ECB decrypt
                    {
                        string plaintext;
                        auto start = std::chrono::high_resolution_clock::now();
                        for (int i = 0; i < 1000; ++i) 
                        {
                            plaintext = ECB_decrypt(cipher); 
                        }
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 1000.0;
                        std::cout << "Average time for decryption over 1000 rounds: " << averageTime << " ms" << std::endl;
                        if (display == 1)
                            cout << "Recovered text: " << plaintext << endl;
                        else if (display == 2)
                        {
                            write2File(plaintext);
                        }
                        else
                        {
                            cout << "Invalid option";
                            return 0;
                        }
                        break;
                    }
                    case 2: // CBC decrypt
                    {
                        string plaintext;
                        auto start = std::chrono::high_resolution_clock::now();
                        for (int i = 0; i < 1000; ++i) 
                        {
                            plaintext = CBC_decrypt(cipher); 
                        }
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 1000.0;
                        std::cout << "Average time for decryption over 1000 rounds: " << averageTime << " ms" << std::endl;
                        if (display == 1)
                            cout << "Recovered text: " << plaintext << endl;
                        else if (display == 2)
                        {
                            write2File(plaintext);
                        }
                        else
                        {
                            cout << "Invalid option";
                            return 0;
                        }
                        break;                 
                    }
                    case 3: // OFB decrypt
                    {
                        string plaintext;
                        auto start = std::chrono::high_resolution_clock::now();
                        for (int i = 0; i < 1000; ++i) 
                        {
                            plaintext = OFB_decrypt(cipher); 
                        }
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 1000.0;
                        std::cout << "Average time for decryption over 1000 rounds: " << averageTime << " ms" << std::endl;
                        if (display == 1)
                            cout << "Recovered text: " << plaintext << endl;
                        else if (display == 2)
                        {
                            write2File(plaintext);
                        }
                        else
                        {
                            cout << "Invalid option";
                            return 0;
                        }
                        break;
                    }
                    case 4: // CFB decrypt
                    {
                        string plaintext;
                        auto start = std::chrono::high_resolution_clock::now();
                        for (int i = 0; i < 1000; ++i) 
                        {
                            plaintext = CFB_decrypt(cipher); 
                        }
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 1000.0;
                        std::cout << "Average time for decryption over 1000 rounds: " << averageTime << " ms" << std::endl;
                        if (display == 1)
                            cout << "Recovered text: " << plaintext << endl;
                        else if (display == 2)
                        {
                            write2File(plaintext);
                        }
                        else
                        {
                            cout << "Invalid option";
                            return 0;
                        }
                        break;
                    }
                    case 5: // CTR decrypt
                    {
                        string plaintext;
                        auto start = std::chrono::high_resolution_clock::now();
                        for (int i = 0; i < 1000; ++i) 
                        {
                            plaintext = CTR_decrypt(cipher); 
                        }
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 1000.0;
                        std::cout << "Average time for decryption over 1000 rounds: " << averageTime << " ms" << std::endl;
                        if (display == 1)
                            cout << "Recovered text: " << plaintext << endl;
                        else if (display == 2)
                        {
                            write2File(plaintext);
                        }
                        else
                        {
                            cout << "Invalid option";
                            return 0;
                        }
                        break;
                    }
                    case 6: // XTS decrypt
                    {
                        string plaintext;
                        auto start = std::chrono::high_resolution_clock::now();
                        for (int i = 0; i < 1000; ++i) 
                        {
                            plaintext = XTS_decrypt(cipher); 
                        }
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 1000.0;
                        std::cout << "Average time for decryption over 1000 rounds: " << averageTime << " ms" << std::endl;
                        if (display == 1)
                            cout << "Recovered text: " << plaintext << endl;
                        else if (display == 2)
                        {
                            write2File(plaintext);
                        }
                        else
                        {
                            cout << "Invalid option";
                            return 0;
                        }
                        break;
                    }
                    case 7: // CCM decrypt
                    {
                        auto start = std::chrono::high_resolution_clock::now();
                        string rpdata;
                        CryptoPP::byte truncatedIV[13];
	                    memcpy(truncatedIV, iv, 13);
                        for (int i = 0; i < 1000; ++i) 
                        {
                            rpdata = CCM_decrypt(cipher, truncatedIV);
                        }
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 1000.0;
                        std::cout << "Average time for decryption over 1000 rounds: " << averageTime << " ms" << std::endl;
                        if (display == 1)
                        {
                            cout << "Recovered pdata: " << rpdata << endl;
                        }
                        else if (display == 2)
                        {
                            write2File(rpdata);
                        }
                        else
                        {
                            cout << "Invalid option";
                            return 0;
                        }
                        break;
                    }
                    case 8: // GCM decrypt
                    {
                        string AAD;
                        cout << "Enter Additional Authenticated Data(AAD): ";
                        cin >> AAD;
                        auto start = std::chrono::high_resolution_clock::now();
                        pair<string, string> out;
                        for (int i = 0; i < 1000; ++i) 
                        {
                            out = GCM_decrypt(cipher, AAD);
                        }
                        string radata = out.first, rpdata = out.second;
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 1000.0;
                        std::cout << "Average time for decryption over 1000 rounds: " << averageTime << " ms" << std::endl;
                        if (display == 1)
                        {
                            cout << "Recovered pdata: " << rpdata << endl;
                        }
                        else if (display == 2)
                        {
                            write2File(rpdata);
                        }
                        else
                        {
                            cout << "Invalid option";
                            return 0;
                        }
                        cout << "Recovered adata: " << radata << endl;
                        break;
                    }
                    default:
                    {
                        cout << "Invalid option";
                        return 0;
                    }
                }
                return 0;
            }
            default:
            {
                cout << "Invalid input\n";
                return 0;
            }    
        }
    }
    return 0;
}