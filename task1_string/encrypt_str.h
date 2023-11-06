//C internal library 
#include <iostream>
using std::endl;
#include <string>
using std::string;
using std::string;
#include <cstdlib>
using std::exit;
#include <fstream>
#include <utility>
#include "assert.h"
//Cryptopp Librari
#include <cryptopp/files.h>
using CryptoPP::FileSource;
using CryptoPP::FileSink;
using CryptoPP::BufferedTransformation;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::Redirector; // string to bytes

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;
#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;

// convert string
// Hex <---> Binary
#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

// Base64 <---> Binary
#include "cryptopp/base64.h"
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

// Block cipher
#include "cryptopp/des.h"
using CryptoPP::DES;
#include "cryptopp/aes.h"
using CryptoPP::AES;

//Mode of operations
#include "cryptopp/modes.h" //ECB, CBC, CBC-CTS, CFB, OFB, CTR
using CryptoPP::ECB_Mode;
using CryptoPP::CBC_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::OFB_Mode;
using CryptoPP::CTR_Mode;
#include "cryptopp/xts.h"
using CryptoPP::XTS;
#include <cryptopp/ccm.h>
using CryptoPP::CCM;
#include "cryptopp/gcm.h"
using CryptoPP::GCM;
//Ref: more here https://www.cryptopp.com/wiki/AEAD_Comparison


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
using  std::codecvt_utf8;

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif

using namespace std;
using namespace CryptoPP;
CryptoPP::byte key[AES::MAX_KEYLENGTH];
CryptoPP::byte iv[AES::BLOCKSIZE];

string b64decode(string enc)
{
    string out;
    StringSource(enc, true, new Base64Decoder(new StringSink(out)));
    return out;
}

string b64encode(string text)
{
    string encoded;
    StringSource(text, true, new Base64Encoder(new StringSink(encoded), true));
    return encoded;
}

string ECB_encrypt(string &plain)
{
    string cipher;
    ECB_Mode< AES >::Encryption e;
	e.SetKey(key, AES::MAX_KEYLENGTH);
	StringSource(plain, true, 
		new StreamTransformationFilter(e,
			new StringSink(cipher)
		) // StreamTransformationFilter      
	); // StringSource
    return cipher;
}

string CBC_encrypt(string &plain)
{
    string cipher;
    CBC_Mode< AES >::Encryption e;
    e.SetKeyWithIV(key, sizeof(key), iv);
    // The StreamTransformationFilter removes
    //  padding as required.
    StringSource s(plain, true, 
        new StreamTransformationFilter(e,
            new StringSink(cipher)
        ) // StreamTransformationFilter
    ); // StringSource
    return cipher;
}

string OFB_encrypt(string &plain)
{
    string cipher;

    OFB_Mode< AES >::Encryption e;
    e.SetKeyWithIV(key, sizeof(key), iv);
    // OFB mode must not use padding. Specifying
    //  a scheme will result in an exception
    StringSource(plain, true, 
        new StreamTransformationFilter(e,
            new StringSink(cipher)
        ) // StreamTransformationFilter      
    ); // StringSource
    return cipher;
}

string CFB_encrypt(string &plain)
{
    string cipher;

    CFB_Mode< AES >::Encryption e;
    e.SetKeyWithIV(key, sizeof(key), iv);
    // CFB mode must not use padding. Specifying
    //  a scheme will result in an exception
    StringSource(plain, true, 
        new StreamTransformationFilter(e,
            new StringSink(cipher)
        ) // StreamTransformationFilter      
    ); // StringSource
    return cipher;
}

string CTR_encrypt(string &plain)
{
    string cipher;

    CTR_Mode< AES >::Encryption e;
    e.SetKeyWithIV(key, sizeof(key), iv);

    // The StreamTransformationFilter adds padding
    //  as required. ECB and CBC Mode must be padded
    //  to the block size of the cipher.
    StringSource(plain, true, 
        new StreamTransformationFilter(e,
            new StringSink(cipher)
        ) // StreamTransformationFilter      
    ); // StringSource

    return cipher;
}

string XTS_encrypt(string &plain)
{
    string cipher;

    XTS_Mode< AES >::Encryption enc;
    enc.SetKeyWithIV( key, sizeof(key), iv );
    // The StreamTransformationFilter adds padding
    //  as requiredec. ECB and XTS Mode must be padded
    //  to the block size of the cipher.
    StringSource ss( plain, true, 
        new StreamTransformationFilter( enc,
            new StringSink( cipher ),
            StreamTransformationFilter::NO_PADDING
        ) // StreamTransformationFilter      
    ); // StringSource

    return cipher;
}

string CCM_encrypt(string &pdata, CryptoPP::byte* truncatedIV)
{
	string cipher;
	const int TAG_SIZE = 8;
	CCM< AES, TAG_SIZE >::Encryption e;
    e.SetKeyWithIV( key, sizeof(key), truncatedIV, sizeof(truncatedIV));
    e.SpecifyDataLengths( 0, pdata.size(), 0);
    StringSource( pdata, true,
        new AuthenticatedEncryptionFilter( e,
            new StringSink( cipher )
        ) // AuthenticatedEncryptionFilter
    ); // StringSource
    return cipher;
}

string GCM_encrypt(string pdata, string adata)
{
	const int TAG_SIZE = 16;
	string cipher;

    GCM< AES >::Encryption e;
    e.SetKeyWithIV( key, sizeof(key), iv, sizeof(iv) );

    AuthenticatedEncryptionFilter ef( e,
        new StringSink( cipher ), false, TAG_SIZE
    ); // AuthenticatedEncryptionFilter

    ef.ChannelPut( "AAD", (const CryptoPP::byte*)adata.data(), adata.size() );
    ef.ChannelMessageEnd("AAD");

    ef.ChannelPut( "", (const CryptoPP::byte*)pdata.data(), pdata.size() );
    ef.ChannelMessageEnd("");
    return cipher;
}


