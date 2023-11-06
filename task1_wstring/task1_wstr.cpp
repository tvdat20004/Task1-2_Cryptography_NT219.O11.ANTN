#include "encrypt_wstr.h"
#include "decrypt_wstr.h"
#include <chrono>

void get_keyboard_key_iv(int mode)
{
    // Nhap key tu ban phim (dang hex)
    wstring key_wstr;
    wcout<<L"Enter key (in hex):";
    wcin >> key_wstr;
    wcin.ignore();

    // decode key tu hex -> byte
    string keyHex = wstring_to_string(key_wstr);

    StringSource(keyHex, true, new HexEncoder(new ArraySink(key, sizeof(key))));

    if (mode != 1)
    {
        // nhap iv tu ban phim
        wstring iv_wstr;
        wcout<<L"Enter IV (in hex):";
        wcin >> iv_wstr;
        wcin.ignore();
    
        // decode iv tu hex -> byte
        string ivHex = wstring_to_string(iv_wstr);
        StringSource(ivHex, true, new HexEncoder(new ArraySink(iv, sizeof(iv))));
    }
}

void get_key_iv_from_file(wstring filenameKey, wstring filenameIV)
{
    // Reading key from file
    string fileKey = wstring_to_string(filenameKey);
    FileSource(fileKey.data(), true, new HexDecoder(new ArraySink(key, sizeof(key))));
    if (filenameIV != L"")
    {
        // Reading IV from file
        string fileIV = wstring_to_string(filenameIV);
        FileSource(fileIV.data(), true, new HexDecoder(new ArraySink(iv, sizeof(iv))));
    }
}

wstring getPlainFromFile(wstring filename)
{
    string fname = wstring_to_string(filename), file_data;
    FileSource(fname.data(), true, new StringSink(file_data));
    return string_to_wstring(file_data);
}

wstring enter(wstring kindOfText)
{
    int selection;
    wstring text;
    wcout<< L"How do you want to enter "<<kindOfText<< ":\n"
    <<L"1.From keyboard\n"
    <<L"2.From file\n"
    <<L"Please enter a number (1-2):";
    wcin >> selection;
    wcin.ignore();
    switch (selection)
    {
        case 1:
        {
            wcout <<L"Enter " << kindOfText<< ": ";
            wcin.ignore();
            getline(wcin, text);
            break;  
        }
        case 2:
        {
            wstring filename;
            wcout<<L"Enter filename: ";
            wcin >> filename;
            text = getPlainFromFile(filename);
        }
        default:
            break;
    }
    return text;
}

void write2File(wstring text)
{
    wstring filename;
    wcout << "Enter filename:";
    wcin.ignore();
    wcin >> filename;
    
    string str_text = wstring_to_string(text);
    ofstream file(wstring_to_string(filename));
    if (file.is_open()) 
    {
        file << wstring_to_string(text);
        file.close();
    } 
    else 
        cerr << "Can't open file" << std::endl;
    wcout << L"Complete writting to "<< filename << endl;
}

int main(int argc, char* argv[])
{
    #ifdef __linux__
    setlocale(LC_ALL, "");
    #elif _WIN32
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
    #endif
    while(true)
    {
        // chon mode
        int mode;
        wcout <<L"Choose your mode:\n"
        << L"1.ECB, 2.CBC, 3.OFB, 4.CFB, 5.CTR, 6.XTS, 7.CCM, 8.GCM\n";
        wcin >> mode;

        // Encrypt or decrypt 
        int select;
        wcout << L"Would you like to encrypt or decrypt message:\n"
            << L"1. Generate key and iv ;\n"
            << L"2. Encrypt;\n"
            << L"3. Decrypt;\n"
            << L"Please enter your number?\n";
        wcin >> select;

        switch (select) 
        {
            case 1: // gen key va IV
            {
                int keygen;
                wcout<<L"How do you want to gen key:\n"
                << L"1.Random\n"
                << L"2.Input from screen\n"
                << L"3.Input from file\n"
                << L"Please enter a number (1-3):";
                wcin >> keygen;
                switch (keygen)
                {
                    case 1: // random key va iv
                    {
                        //random key
                        AutoSeededRandomPool prng;
                        prng.GenerateBlock(key, sizeof(key));
                        string encodedKey;
                        StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encodedKey)));        
                        wcout << L"Generated Key: " << string_to_wstring(encodedKey) << endl;
                        
                        //random IV
                        if (mode != 1) 
                        {
                            string encodedIV;
                            prng.GenerateBlock(iv, sizeof(iv));
                            StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encodedIV)));
                            
                            wcout << L"Generated IV: " << string_to_wstring(encodedIV) << endl;
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
                        wstring filenameKey;
                        wcout<<L"Enter key file name:";
                        wcin >> filenameKey;
                        if (mode != 1)
                        {
                            wstring filenameIV;
                            wcout<<L"Enter IV file name:";
                            wcin >> filenameIV;
                            get_key_iv_from_file(filenameKey, filenameIV);
                            break;
                        }
                        else
                            get_key_iv_from_file(filenameKey, L"");
                        break;
                    }
                    default:
                    {
                        wcout<<L"Invalid option";
                        return 0;
                    }
                }
                break;
            }
            case 2: // Encrypt du lieu
            {
                // Nhap plaintext
                wstring plain;
                plain = enter(L"plaintext"); 
                int display;
                string plaintext = wstring_to_string(plain);
                wcout<< L"How do you want to display output:\n"
                << L"1.Display in screen\n"
                << L"2.Write on file\n"
                << L"Please choose a number(1-2): ";
                wcin >> display;
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
                        wcout << L"Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
                        wstring ciphertext = b64encode(cipher);
                        if (display == 1)
                            wcout<<L"Ciphertext(base 64):" << ciphertext << endl;
                        else if (display == 2)
                        {
                            write2File(ciphertext);
                        }
                        else
                        {
                            wcout << L"Invalid cipher";
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
                        wcout << L"Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
                        wstring ciphertext = b64encode(cipher);
                        if (display == 1)
                            wcout<<L"Ciphertext(base 64):" << ciphertext << endl;
                        else if (display == 2)
                        {
                            write2File(ciphertext);
                        }
                        else
                        {
                            wcout << L"Invalid cipher";
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
                        wcout << L"Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
                        wstring ciphertext = b64encode(cipher);
                        if (display == 1)
                            wcout<<L"Ciphertext(base 64):" << ciphertext << endl;
                        else if (display == 2)
                        {
                            write2File(ciphertext);
                        }
                        else
                        {
                            wcout << L"Invalid cipher";
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
                        wcout << L"Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
                        wstring ciphertext = b64encode(cipher);
                        if (display == 1)
                            wcout<<L"Ciphertext(base 64):" << ciphertext << endl;
                        else if (display == 2)
                        {
                            write2File(ciphertext);
                        }
                        else
                        {
                            wcout << L"Invalid cipher";
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
                        wcout << L"Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
                        wstring ciphertext = b64encode(cipher);
                        if (display == 1)
                            wcout<<L"Ciphertext(base 64):" << ciphertext << endl;
                        else if (display == 2)
                        {
                            write2File(ciphertext);
                        }
                        else
                        {
                            wcout << L"Invalid cipher";
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
                        wcout << L"Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
                        wstring ciphertext = b64encode(cipher);
                        if (display == 1)
                            wcout<<L"Ciphertext(base 64):" << ciphertext << endl;
                        else if (display == 2)
                        {
                            write2File(ciphertext);
                        }
                        else
                        {
                            wcout << L"Invalid cipher";
                            return 0;
                        }
                        break;
                    }
                    case 7: // CCM encrypt
                    {
                        wstring wAAD;
                        wcout << L"Enter Additional Authenticated Data(AAD): "; 
                        wcin >> wAAD;
                        
                        string cipher, AAD = wstring_to_string(wAAD);
                        auto start = std::chrono::high_resolution_clock::now();
                        CryptoPP::byte truncatedIV[13];
	                    memcpy(truncatedIV, iv, 13);
                        for (int i = 0; i < 1000; ++i) 
                        {
                            cipher = CCM_encrypt(plaintext, AAD, truncatedIV); 
                        }
                        wstring ciphertext = b64encode(cipher);
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 1000.0;
                        std::wcout << L"Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
                        if (display == 1)
                            wcout << L"Ciphertext base64 (enc + tag):" << ciphertext << endl;
                        else if (display == 2)
                        {
                            write2File(ciphertext);
                        }
                        else
                        {
                            wcout << L"Invalid cipher";
                            return 0;
                        }
                        break;
                        
                    }
                    case 8: // GCM encrypt
                    {
                        wstring wAAD;
                        wcout << L"Enter Additional Authenticated Data(AAD): "; 
                        wcin >> wAAD;
                        
                        string cipher, AAD = wstring_to_string(wAAD);
                        auto start = std::chrono::high_resolution_clock::now();
                        for (int i = 0; i < 1000; ++i) 
                        {
                            cipher = GCM_encrypt(plaintext, AAD); 
                        }
                        wstring ciphertext = b64encode(cipher);
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 1000.0;
                        std::wcout << L"Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
                        if (display == 1)
                            wcout << L"Ciphertext base64 (enc + tag):" << ciphertext << endl;
                        else if (display == 2)
                        {
                            write2File(ciphertext);
                        }
                        else
                        {
                            wcout << L"Invalid cipher";
                            return 0;
                        }
                        break;
                    }
                    default:
                    {
                        wcout<<L"Invalid option";
                        return 0;
                    }
                }
                break;
            }
            case 3: // Decrypt du lieu
            {
                // Nhap ciphertext
                wstring wcipher = enter(L"ciphertext(base 64)");
                int display;
                string cipher = b64decode(wcipher);
                wcout<< L"How do you want to display output:\n"
                << L"1.Display in screen\n"
                << L"2.Write on file\n"
                << L"Please choose a number(1-2): ";
                wcin >> display;
                switch (mode)
                {
                    case 1: // ECB decrypt
                    {
                        string plain;
                        auto start = std::chrono::high_resolution_clock::now();
                        for (int i = 0; i < 1000; ++i) 
                        {
                            plain = ECB_decrypt(cipher); 
                        }
                        wstring plaintext = string_to_wstring(plain);
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 1000.0;
                        std::wcout << L"Average time for decryption over 1000 rounds: " << averageTime << " ms" << std::endl;
                        if (display == 1)
                            wcout << L"Recovered text: " << plaintext << endl;
                        else if (display == 2)
                        {
                            write2File(plaintext);
                        }
                        else
                        {
                            wcout << L"Invalid option";
                            return 0;
                        }
                        break;
                    }
                    case 2: // CBC decrypt
                    {
                        string plain;
                        auto start = std::chrono::high_resolution_clock::now();
                        for (int i = 0; i < 1000; ++i) 
                        {
                            plain = CBC_decrypt(cipher); 
                        }
                        wstring plaintext = string_to_wstring(plain);
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 1000.0;
                        std::wcout << L"Average time for decryption over 1000 rounds: " << averageTime << " ms" << std::endl;
                        if (display == 1)
                            wcout << L"Recovered text: " << plaintext << endl;
                        else if (display == 2)
                        {
                            write2File(plaintext);
                        }
                        else
                        {
                            wcout << L"Invalid option";
                            return 0;
                        }
                        break;                 
                    }
                    case 3: // OFB decrypt
                    {
                        string plain;
                        auto start = std::chrono::high_resolution_clock::now();
                        for (int i = 0; i < 1000; ++i) 
                        {
                            plain = OFB_decrypt(cipher); 
                        }
                        wstring plaintext = string_to_wstring(plain);
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 1000.0;
                        std::wcout << L"Average time for decryption over 1000 rounds: " << averageTime << " ms" << std::endl;
                        if (display == 1)
                            wcout << L"Recovered text: " << plaintext << endl;
                        else if (display == 2)
                        {
                            write2File(plaintext);
                        }
                        else
                        {
                            wcout << L"Invalid option";
                            return 0;
                        }
                        break;
                    }
                    case 4: // CFB decrypt
                    {
                        string plain;
                        auto start = std::chrono::high_resolution_clock::now();
                        for (int i = 0; i < 1000; ++i) 
                        {
                            plain = CFB_decrypt(cipher); 
                        }
                        wstring plaintext = string_to_wstring(plain);
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 1000.0;
                        std::wcout << L"Average time for decryption over 1000 rounds: " << averageTime << " ms" << std::endl;
                        if (display == 1)
                            wcout << L"Recovered text: " << plaintext << endl;
                        else if (display == 2)
                        {
                            write2File(plaintext);
                        }
                        else
                        {
                            wcout << L"Invalid option";
                            return 0;
                        }
                        break;
                    }
                    case 5: // CTR decrypt
                    {
                        string plain;
                        auto start = std::chrono::high_resolution_clock::now();
                        for (int i = 0; i < 1000; ++i) 
                        {
                            plain = CTR_decrypt(cipher); 
                        }
                        wstring plaintext = string_to_wstring(plain);
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 1000.0;
                        std::wcout << L"Average time for decryption over 1000 rounds: " << averageTime << " ms" << std::endl;
                        if (display == 1)
                            wcout << L"Recovered text: " << plaintext << endl;
                        else if (display == 2)
                        {
                            write2File(plaintext);
                        }
                        else
                        {
                            wcout << L"Invalid option";
                            return 0;
                        }
                        break;
                    }
                    case 6: // XTS decrypt
                    {
                        string plain;
                        auto start = std::chrono::high_resolution_clock::now();
                        for (int i = 0; i < 1000; ++i) 
                        {
                            plain = XTS_decrypt(cipher); 
                        }
                        wstring plaintext = string_to_wstring(plain);
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 1000.0;
                        std::wcout << L"Average time for decryption over 1000 rounds: " << averageTime << " ms" << std::endl;
                        if (display == 1)
                            wcout << L"Recovered text: " << plaintext << endl;
                        else if (display == 2)
                        {
                            write2File(plaintext);
                        }
                        else
                        {
                            wcout << L"Invalid option";
                            return 0;
                        }
                        break;
                    }
                    case 7: // CCM decrypt
                    {
                        wstring wAAD;
                        wcout << L"Enter Additional Authenticated Data(AAD): ";
                        wcin >> wAAD;
                        auto start = std::chrono::high_resolution_clock::now();
                        wstring radata, rpdata;
                        string AAD = wstring_to_string(wAAD);
                        pair<string, string> out;
                        CryptoPP::byte truncatedIV[13];
	                    memcpy(truncatedIV, iv, 13);
                        for (int i = 0; i < 10000; ++i) 
                        {
                            out = CCM_decrypt(cipher, AAD, truncatedIV);
                        }
                        radata = string_to_wstring(out.first);
                        rpdata = string_to_wstring(out.second);
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 10000.0;
                        std::wcout << L"Average time for decryption over 10000 rounds: " << averageTime << " ms" << std::endl;
                        if (display == 1)
                        {
                            wcout << L"Recovered pdata: " << rpdata << endl;
                        }
                        else if (display == 2)
                        {
                            write2File(rpdata);
                        }
                        else
                        {
                            wcout << L"Invalid option";
                            return 0;
                        }
                        wcout << L"Recovered adata: " << radata << endl;
                        break;
                    }
                    case 8: // GCM decrypt
                    {
                        wstring wAAD;
                        wcout << L"Enter Additional Authenticated Data(AAD): ";
                        wcin >> wAAD;
                        auto start = std::chrono::high_resolution_clock::now();
                        wstring radata, rpdata;
                        string AAD = wstring_to_string(wAAD);
                        pair<string, string> out;
                        for (int i = 0; i < 10000; ++i) 
                        {
                            out = GCM_decrypt(cipher, AAD);
                        }
                        radata = string_to_wstring(out.first);
                        rpdata = string_to_wstring(out.second);
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 10000.0;
                        std::wcout << L"Average time for decryption over 10000 rounds: " << averageTime << " ms" << std::endl;
                        if (display == 1)
                        {
                            wcout << L"Recovered pdata: " << rpdata << endl;
                        }
                        else if (display == 2)
                        {
                            write2File(rpdata);
                        }
                        else
                        {
                            wcout << L"Invalid option";
                            return 0;
                        }
                        wcout << L"Recovered adata: " << radata << endl;
                        break;
                    }
                    default:
                    {
                        wcout << L"Invalid option";
                        return 0;
                    }
                }
                return 0;
            }
            default:
            {
                wcout << "Invalid input\n";
                return 0;
            }    
        }
    }
    return 0;
}