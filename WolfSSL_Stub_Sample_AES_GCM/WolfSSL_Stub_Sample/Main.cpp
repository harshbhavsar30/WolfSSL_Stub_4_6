#include <iostream>
#include <openssl/evp.h>

#define GCM_AUTH_TAG_LEN 16

void Create_Context(EVP_CIPHER_CTX** ctx);
int Destroy_Context(EVP_CIPHER_CTX* ctx);
int Init_Context(EVP_CIPHER_CTX* ctx, const EVP_CIPHER** evp, const uint8_t* key, int KeySize);
int Set_IV(EVP_CIPHER_CTX* ctx, uint8_t* iv, int isEncDir);
int Set_aad(EVP_CIPHER_CTX* ctx, unsigned char* inbuf, int tagLen, int addLen, unsigned char dummy_tag[GCM_AUTH_TAG_LEN]);
void Encrypt_Data(EVP_CIPHER_CTX* ctx, unsigned char* inbuf, unsigned char* Outbuf, int encLen, unsigned char* AuthTag, int tag_len);
int Decrypt_Data(EVP_CIPHER_CTX* ctx, unsigned char* EncData, unsigned char* DecData, int encLen, int tag_len);
void print_buffer(const char* name, unsigned char* data, int len);


int main()
{
    //Declaration: Start
    EVP_CIPHER_CTX* ctxEnc;
    const EVP_CIPHER* evpEnc = NULL;

    EVP_CIPHER_CTX* ctxDec;
    const EVP_CIPHER* evpDec = NULL;

    int tag_len = 16;
    int encLen;
    unsigned char dummy_tag[GCM_AUTH_TAG_LEN] = { 0 };
    
    const uint8_t key[] = { 0x21 ,0x60 ,0x41 ,0xcf ,0x6f ,0x9a ,0xe9 ,0xec ,0xad ,0xe9 ,0x48 ,0x4b ,0x5f ,0xab ,0xfe ,0x03 };
    
    int KeySize = 16;
    uint8_t iv[] = { 0x3a ,0xaf ,0x78 ,0x8e ,0xfb ,0x80 ,0xfc ,0x02 ,0x4b ,0xbb ,0xe8 ,0x62 };
    unsigned char aad_4Bytes[] = { 0x80,0x00,0x00,0x01 };
    //ASCII Data: "This is Test String. AESGCM128 algorithm is being used for encryption and decryption"
    unsigned char inbuf[] =   { 0x9b ,0xcc ,0x00 ,0x16 ,0x96 ,0xfc ,0x98 ,0xc7 , 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x2e, 0x20, 0x41, 0x45, 0x53, 0x47, 0x43, 0x4d, 0x31, 0x32, 0x38, 0x20, 0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x20, 0x69, 0x73, 0x20, 0x62, 0x65, 0x69, 0x6e, 0x67, 0x20, 0x75, 0x73, 0x65, 0x64, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x64, 0x65, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e };
    unsigned char Outbuf[256] = { 0 };
    unsigned char EncPacket[256] = { 0 };
    unsigned char DecPacket[256] = { 0 };
    unsigned char WolfDecPacket[256] = { 0 };
    unsigned char AuthTag[16] = { 0 };
    //Declaration: End


    //Create & Init Context
    Create_Context(&ctxEnc);
    Init_Context(ctxEnc, &evpEnc, key, KeySize);

    encLen = sizeof(inbuf) - 8;

    // ========================== Encryption START ========================== //
    //Setting IV
    if (0 != Set_IV(ctxEnc, iv, 1))
    {
        printf("Set_IV Failed\n");
        return -1;
    }

    //Setting aad : 8 Bytes
    if (0 != Set_aad(ctxEnc, inbuf, 16, 8, dummy_tag))
    {
        printf("Set_aad_8 Failed\n");
        return -1;
    }

    //Setting aad : 4 Bytes
    if (0 != Set_aad(ctxEnc, aad_4Bytes, 16, 4, dummy_tag))
    {
        printf("Set_aad_8 Failed\n");
        return -1;
    }


    print_buffer("RAW Data:", inbuf, 8 + encLen);

    //Encrypting Data
    Encrypt_Data(ctxEnc, inbuf, Outbuf, encLen, AuthTag, tag_len);

    print_buffer("\n\nAuth Tag:", AuthTag, tag_len);

    memcpy(EncPacket, inbuf, 8);
    memcpy(EncPacket + 8, Outbuf, encLen);
    memcpy(EncPacket + 8 + encLen, AuthTag, tag_len);

    print_buffer("\nPacket Data (Encrypted by WolfSSL):", EncPacket, 8 + encLen + tag_len);

    Destroy_Context(ctxEnc);
    // ========================== Encryption END ========================== //
}

void Create_Context(EVP_CIPHER_CTX** ctx)
{
    *ctx = EVP_CIPHER_CTX_new();
}

int Init_Context(EVP_CIPHER_CTX* ctx, const EVP_CIPHER** evp, const uint8_t* key, int KeySize)
{
    switch (KeySize) {
    case 32/*SRTP_AES_256_KEY_LEN*/:
        *evp = EVP_aes_256_gcm();
        break;
    case 16/*SRTP_AES_128_KEY_LEN*/:
        *evp = EVP_aes_128_gcm();
        break;
    }

    if (!EVP_CipherInit_ex(ctx, *evp, NULL, key, NULL, 0)) {
        return -1;
    }

    return 0;
}

int Set_IV(EVP_CIPHER_CTX* ctx, uint8_t* iv, int isEncDir)
{
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, 0)) {
        return -1;
    }
    if (!EVP_CipherInit_ex(ctx, NULL, NULL, NULL, iv, isEncDir))
    {
        return -1;
    }
    return 0;
}

int Set_aad(EVP_CIPHER_CTX* ctx, unsigned char* inbuf, int tagLen, int addLen, unsigned char dummy_tag[GCM_AUTH_TAG_LEN])
{
    int retVal;
    memset(dummy_tag, 0x0, GCM_AUTH_TAG_LEN);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tagLen, &dummy_tag);

    retVal = EVP_Cipher(ctx, NULL, inbuf, addLen);/* == 1 ? addLen : -1;
    if (retVal != addLen) {
        return -1;
    }*/
    return 0;
}

void Encrypt_Data(EVP_CIPHER_CTX* ctx, unsigned char* inbuf, unsigned char* Outbuf, int encLen, unsigned char* AuthTag, int tag_len)
{
    //Encrypt Data
    EVP_Cipher(ctx, Outbuf, inbuf + 8, encLen);

    // Calculate the tag
    EVP_Cipher(ctx, NULL, NULL, 0);

    // Retreive the tag
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, AuthTag);
}

int Decrypt_Data(EVP_CIPHER_CTX* ctx, unsigned char* EncData, unsigned char* DecData, int encLen, int tag_len)
{
    int retVal;

    retVal = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, EncData + 8 + encLen);

    retVal = EVP_Cipher(ctx, DecData + 8, EncData + 8, encLen);

    if (-1 == retVal) //4.6
    //if (0 == retVal)
    {
        printf("\nEVP_Cipher FAILED\n");
        return -1;
    }
    /*
    * Check the tag
    */
    if (-1 == EVP_Cipher(ctx, NULL, NULL, 0)) { //4.6
    //if (EVP_Cipher(ctx, NULL, NULL, 0)) {
        printf("\nTag Check FAILED\n");
        return -1;
    }

    return 0;
}

int Destroy_Context(EVP_CIPHER_CTX* ctx)
{
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }

    return 0;
}

//Print Buffer in HEX
void print_buffer(const char* name, unsigned char* data, int len)
{
    int i; printf("%s", name); for (i = 0; i < len; i++) { if ((i % 8) == 0) printf("\n "); printf("0x%02x, ", data[i]); } printf("\n");
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   5. In the future, to open this project again, go to File > Open > Project and select the .sln file
