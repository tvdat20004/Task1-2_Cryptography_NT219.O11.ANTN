
bytes urandom(int n)
{
    bytes arr(16);
    srand(time(NULL));
    for (int i = 0; i < n; i++)
    {
        arr[i] = rand() % 256;
    }
    return arr;
}

class modes
{
public:
    bytes iv;
    int key_length;
    AES aes;
    
    modes(bytes key)
    {
        key_length = key.size() * 8;
        if (key_length != 128 && key_length != 192 && key_length != 256)
        {
            throw invalid_argument("Invalid key length. Supported lengths are 128, 192, and 256 bits.");
        }
        aes = AES(key, key_length);
        iv = urandom(16);

    }
    
    bytes pkcs7_padding(bytes data)
    {
        int padding_length = 16 - (data.size() % 16);
        bytes padding_data(padding_length, padding_length);
        data.insert(data.end(), padding_data.begin(), padding_data.end());   
        return data;
    }

    bytes pkcs7_unpadding(bytes data)
    {
        int padding_length = data[data.size() - 1];
        bytes unpadded_data;
        for (int i = 0; i < data.size() - padding_length; i++)
        {
            unpadded_data.push_back(data[i]);
        }
        return unpadded_data;
    }

    bytes cbc_encrypt(bytes plaintext)
    {

        bytes padded_data = pkcs7_padding(plaintext);
            
        vector<bytes > encrypted_blocks;
        bytes previous_block = iv;

        cout << "The Inital Vector IV: " << hex(previous_block) << endl;
        for (int i = 0; i < padded_data.size(); i += 16)
        {
            bytes block;
            for (int j = i; j < 16 + i; j++)
            {
                block.push_back(padded_data[j]);
            }
            for (int j = 0; j < 16; j++)
                block[j] = block[j] ^ previous_block[j];

            bytes encrypted_block = aes.encrypt(block);
            encrypted_blocks.push_back(encrypted_block);
            previous_block = encrypted_block;
        }
        bytes res = iv;
        for (auto block : encrypted_blocks)
        {
            res = concat(res, block);
        }
        return res;
    }

    bytes cbc_decrypt(bytes ciphertext)
    {
        if (ciphertext.size() % 16 != 0)
            throw invalid_argument("Ciphertext length must be a multiple of 16 bytes for CBC mode.");
        bytes iv_, cipher;
        for (int i = 0; i < ciphertext.size(); i++)
        {
            if (i < 16)
                iv_.push_back(ciphertext[i]);
            else
                cipher.push_back(ciphertext[i]);
        }
        ciphertext = cipher;
        cout << "The Initial Vector IV: "<< hex(iv) << endl;
        vector<bytes > decrypted_blocks;
        bytes previous_block = iv;
        for (int i = 0; i < ciphertext.size(); i += 16)
        {
            bytes block;
            for (int j = i; j < i + 16; j++ )
            {
                block.push_back(ciphertext[j]);
            }
            bytes decrypted_block = aes.decrypt(block);

            for (int j = 0; j < 16; j++)
            {
                decrypted_block[j] = decrypted_block[j] ^ previous_block[j];
            }
            decrypted_blocks.push_back(decrypted_block);
            previous_block = block;
        }
        bytes decrypted_data = decrypted_blocks[0];
        for (int i = 1; i < decrypted_blocks.size(); i++)
        {
            decrypted_data = concat(decrypted_data, decrypted_blocks[i]);
        }
        return pkcs7_unpadding(decrypted_data);
    }

};
