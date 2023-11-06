

string ECB_decrypt(string &cipher)
{
    string plain;
    ECB_Mode< AES >::Decryption d;
    d.SetKey(key, sizeof(key));
    // The StreamTransformationFilter removes
    //  padding as required.
    StringSource s(cipher, true, 
        new StreamTransformationFilter(d,
            new StringSink(plain)
        ) // StreamTransformationFilter
    ); // StringSource
    return plain;
}

string CBC_decrypt(string &cipher)
{
    string recovered;

    CBC_Mode< AES >::Decryption d;
    d.SetKeyWithIV(key, sizeof(key), iv);
    // The StreamTransformationFilter removes
    //  padding as required.
    StringSource s(cipher, true, 
        new StreamTransformationFilter(d,
            new StringSink(recovered)
        ) // StreamTransformationFilter
    ); // StringSource
    return recovered;
}

string OFB_decrypt(string &ciphertext)
{
    string recovered;
    OFB_Mode< AES >::Decryption d;
    d.SetKeyWithIV(key, sizeof(key), iv);

    // The StreamTransformationFilter removes
    //  padding as required.
    StringSource s(ciphertext, true, 
        new StreamTransformationFilter(d,
            new StringSink(recovered)
        ) // StreamTransformationFilter
    ); // StringSource
    return recovered;
}

string CFB_decrypt(string &ciphertext)
{
    string recovered;
   
    CFB_Mode< AES >::Decryption d;
    d.SetKeyWithIV(key, sizeof(key), iv);

    // The StreamTransformationFilter removes
    //  padding as required.
    StringSource s(ciphertext, true, 
        new StreamTransformationFilter(d,
            new StringSink(recovered)
        ) // StreamTransformationFilter
    ); // StringSource
    return recovered;
}

string CTR_decrypt(string &ciphertext)
{
    string recovered;

    CTR_Mode< AES >::Decryption d;
    d.SetKeyWithIV(key, sizeof(key), iv);

    // The StreamTransformationFilter removes
    //  padding as required.
    StringSource s(ciphertext, true, 
        new StreamTransformationFilter(d,
            new StringSink(recovered)
        ) // StreamTransformationFilter
    ); // StringSource
    return recovered;
}

string XTS_decrypt(string &ciphertext)
{
    string recovered;

    XTS_Mode< AES >::Decryption dec;
    dec.SetKeyWithIV( key, sizeof(key), iv );

    // The StreamTransformationFilter removes
    //  padding as requiredec.
    StringSource ss( ciphertext, true, 
        new StreamTransformationFilter( dec,
            new StringSink( recovered ),
            StreamTransformationFilter::NO_PADDING
        ) // StreamTransformationFilter
    ); // StringSource        
	return recovered;
}

pair<string, string> CCM_decrypt(string &cipher, string &adata, CryptoPP::byte* iv_)
{
	const int TAG_SIZE = 8;
	
    string radata, rpdata;
	try
    {
        // Break the cipher text out into it's
        //  components: Encrypted and MAC
        string enc = cipher.substr( 0, cipher.length()-TAG_SIZE );
        string tag = cipher.substr( cipher.length()-TAG_SIZE );
        // Sanity checks
        assert( cipher.size() == enc.size() + tag.size());
        assert( TAG_SIZE == tag.size() );

        // Not recovered - sent via clear channel
        radata = adata;

        CCM< AES, TAG_SIZE >::Decryption d;
        d.SetKeyWithIV( key, sizeof(key), iv_, 13);
        d.SpecifyDataLengths( radata.size(), enc.size(), 0 );

        // Object will not throw an exception
        //  during decryption\verification _if_
        //  verification fails.
        //AuthenticatedDecryptionFilter df( d, NULL,
        // AuthenticatedDecryptionFilter::MAC_AT_BEGIN );

        AuthenticatedDecryptionFilter df( d, NULL,
            //AuthenticatedDecryptionFilter::MAC_AT_BEGIN | 
            AuthenticatedDecryptionFilter::THROW_EXCEPTION );

        // The order of the following calls are important        
        df.ChannelPut( "AAD", (const CryptoPP::byte*)adata.data(), adata.size() );
        df.ChannelPut( "", (const CryptoPP::byte*)enc.data(), enc.size() );
        df.ChannelPut( "", (const CryptoPP::byte*)tag.data(), tag.size() );

        df.ChannelMessageEnd( "AAD" );
        df.ChannelMessageEnd( "" );

        // Remove data from channel
        string retrieved;
        size_t n = (size_t)-1;

        // Plain text recovered from enc.data()
        df.SetRetrievalChannel( "" );
        n = (size_t)df.MaxRetrievable();
        retrieved.resize( n );

        if( n > 0 ) { df.Get( (CryptoPP::byte*)retrieved.data(), n ); }
        rpdata = retrieved;        
    }
    catch( CryptoPP::InvalidArgument& e )
    {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::HashVerificationFilter::HashVerificationFailed& e )
    {
        cerr << "Caught HashVerificationFailed..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    return make_pair(radata,rpdata);
}

pair<string, string> GCM_decrypt(string &cipher, string &adata)
{
	string radata, rpdata;
	const int TAG_SIZE = 16;
	try
    {
        GCM< AES >::Decryption d;
        d.SetKeyWithIV( key, sizeof(key), iv, sizeof(iv) );

        // Break the cipher text out into it's
        //  components: Encrypted Data and MAC Value
        string enc = cipher.substr( 0, cipher.length()-TAG_SIZE );
        string mac = cipher.substr( cipher.length()-TAG_SIZE );

        // Sanity checks
        assert( cipher.size() == enc.size() + mac.size() );
        assert( TAG_SIZE == mac.size() );

        // Not recovered - sent via clear channel
        radata = adata;     

        // Object will not throw an exception
        //  during decryption\verification _if_
        //  verification fails.
        //AuthenticatedDecryptionFilter df( d, NULL,
        // AuthenticatedDecryptionFilter::MAC_AT_BEGIN );

        AuthenticatedDecryptionFilter df( d, NULL,
            AuthenticatedDecryptionFilter::MAC_AT_BEGIN |
            AuthenticatedDecryptionFilter::THROW_EXCEPTION, TAG_SIZE );

        // The order of the following calls are important
        df.ChannelPut( "", (const CryptoPP::byte*)mac.data(), mac.size() );
        df.ChannelPut( "AAD", (const CryptoPP::byte*)adata.data(), adata.size() ); 
        df.ChannelPut( "", (const CryptoPP::byte*)enc.data(), enc.size() );               

        // If the object throws, it will most likely occur
        //  during ChannelMessageEnd()
        df.ChannelMessageEnd( "AAD" );
        df.ChannelMessageEnd( "" );


        // Remove data from channel
        string retrieved;
        size_t n = (size_t)-1;

        // Plain text recovered from enc.data()
        df.SetRetrievalChannel( "" );
        n = (size_t)df.MaxRetrievable();
        retrieved.resize( n );

        if( n > 0 ) { df.Get( (CryptoPP::byte*)retrieved.data(), n ); }
        rpdata = retrieved;
    }
    catch( CryptoPP::InvalidArgument& e )
    {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::AuthenticatedSymmetricCipher::BadState& e )
    {
        // Pushing PDATA before ADATA results in:
        //  "GMC/AES: Update was called before State_IVSet"
        cerr << "Caught BadState..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::HashVerificationFilter::HashVerificationFailed& e )
    {
        cerr << "Caught HashVerificationFailed..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    return make_pair(radata,rpdata);
}

