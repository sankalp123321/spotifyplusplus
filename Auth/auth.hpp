#ifndef _AUTH_HPP_
#define _AUTH_HPP_

#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <ctime>
#include <cstring>

// https://medium.com/bootdotdev/how-sha-2-works-step-by-step-sha-256-90ecd4f09e4d
// https://sha256algorithm.com/
// 

#define BASE64_URL_ENCODING (1)

#define ROUND_UP_DIV(x,y)   (((x) + ((y)-1))/(y))
#define BYTES_IN_U64        (8)
#define BYTES_IN_U32        (4)
#define BITS_IN_BYTE        (8)
// #define MIN(X,Y)            ((X<Y)?X:Y)
// #define MAX(X,Y)            ((X>Y)?X:Y)

// SHA256 Macros
#define SHA256_CHUNK_SIZE               (512)
#define MESSAGE_SCHEUDLE_WORD_COUNT     (64)

#define to_string_conv(X)(std::to_string((X>>24)&0xFF) \
        + std::to_string((X>>16)&0xFF) \
        + std::to_string((X>>8)&0xFF) \
        + std::to_string((X)&0xFF))

#define array_filler_1(INP,OUT,IDX,OFFSET) \
        (OUT[IDX+OFFSET]=((INP>>24)&0xFF))
#define array_filler_2(INP,OUT,IDX,OFFSET) \
        (OUT[IDX+OFFSET]=((INP>>16)&0xFF))
#define array_filler_3(INP,OUT,IDX,OFFSET) \
        (OUT[IDX+OFFSET]=((INP>>8)&0xFF))
#define array_filler_4(INP,OUT,IDX,OFFSET) \
        (OUT[IDX+OFFSET]=((INP)&0xFF))

class auth
{
    public:

    auth()
    {
        /* initialize random seed: */
        srand (time(NULL));
    }

    std::string AuthCodeVerifier(uint32_t length)
    {
        if(length > 128)
        {
            return "";
        }

        std::string possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
        // Select a 128 char long string that selects char randomly
        // Chars allowed - [A-Z] [a-z] [0-9] [-,.,_,~]

        std::vector<char> vec;
        for(uint16_t idx = 0; idx < possible.size(); idx++)
        {
            vec.push_back(possible[idx]);
        }

        std::string codeVerifierString;

        for(uint16_t rand_idx = 0; rand_idx < length; rand_idx++)
        {
            uint32_t idx = rand() % vec.size();
            codeVerifierString += vec[idx];
        }

        printf("Code Verifier string [%s]\n", codeVerifierString.c_str());
        return codeVerifierString;
    }

    std::string AuthCodeChallenge(std::string codeVerifier)
    {
        // printf("Input[%s]\n", codeVerifier.c_str());
        #pragma pack(1)
        typedef union base64
        {
            struct bases
            {
                uint32_t a1 : 6;
                uint32_t a2 : 6;
                uint32_t a3 : 6;
                uint32_t a4 : 6;
            }bases;
            uint32_t word;
        }base64;

#if BASE64_ENCODING
        static const std::string base64Chars = 
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";
#else
    #if BASE64_URL_ENCODING
        static const std::string base64Chars = 
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789-_";
    #endif
#endif
        
        std::string base64EnecodedString = "";
        uint8_t codeVerifierLength = codeVerifier.size();

        uint8_t leftOvers = codeVerifier.length() % 3;
        codeVerifierLength = codeVerifierLength - leftOvers;
        const uint8_t *pBytesPtr = reinterpret_cast<const uint8_t*>(codeVerifier.c_str());
        for(uint32_t idx = 0; idx < codeVerifierLength; )
        {
            base64 b;
            uint32_t val = (*((uint32_t*)pBytesPtr)) & 0x00FFFFFF;
            b.word = ((val >> 16) & 0x0000FF) | (val & 0x00FF00) | ((val << 16) & 0xFF0000);
            // printf("0x%X 0x%X 0x%X 0x%X 0x%X\n", b.word, b.bases.a1, b.bases.a2, b.bases.a3, b.bases.a4);

            base64EnecodedString += base64Chars.at(b.bases.a4);
            base64EnecodedString += base64Chars.at(b.bases.a3);
            base64EnecodedString += base64Chars.at(b.bases.a2);
            base64EnecodedString += base64Chars.at(b.bases.a1);
            idx += 3;
            pBytesPtr += 3;
        }
        
        if(leftOvers)
        {
            uint8_t numCharsNeededToComplete = 3 - leftOvers;
            std::vector<uint8_t> finalStr;
            for (uint8_t i = 0; i < leftOvers; i++)
            {
                finalStr.push_back(codeVerifier[codeVerifierLength+i]);
                // printf("$$$$$$$[%c]\n", codeVerifier[codeVerifierLength+i]);
            }
            
            for (uint8_t i = 0; i < numCharsNeededToComplete; i++)
            {
                finalStr.push_back('\0');
            }
            const uint8_t *pBytesPtr = &finalStr[0];

            base64 b;
            uint32_t val = (*((uint32_t*)pBytesPtr)) & 0x00FFFFFF;
            b.word = ((val >> 16) & 0x0000FF) | (val & 0x00FF00) | ((val << 16) & 0xFF0000);
            // printf("0x%X 0x%X 0x%X 0x%X 0x%X\n", b.word, b.bases.a1, b.bases.a2, b.bases.a3, b.bases.a4);

            base64EnecodedString += base64Chars.at(b.bases.a4);
            base64EnecodedString += base64Chars.at(b.bases.a3);
            base64EnecodedString += base64Chars.at(b.bases.a2);
            base64EnecodedString += base64Chars.at(b.bases.a1);

#if BASE64_URL_ENCODING
            base64EnecodedString.resize(base64EnecodedString.size() - numCharsNeededToComplete);
#else
            uint8_t len = base64EnecodedString.size();
            for (uint8_t i = 0; i < numCharsNeededToComplete; i++)
            {
                base64EnecodedString[len - 1 - i] = '=';
            }
#endif
        }
        // printf("Base 64 URL encoded String [%s]\n", base64EnecodedString.c_str());
        // printf("0x%X 0x%X 0x%X 0x%X 0x%X\n", b.word, b.bases.a1, b.bases.a2, b.bases.a3, b.bases.a4);
        return base64EnecodedString;
    }

    std::string AuthCodeChallenge(std::array<uint8_t, 32> inputArray, uint16_t arraySize)
    {
        // printf("Input[%s]\n", codeVerifier.c_str());
        #pragma pack(1)
        typedef union base64
        {
            struct bases
            {
                uint32_t a1 : 6;
                uint32_t a2 : 6;
                uint32_t a3 : 6;
                uint32_t a4 : 6;
            }bases;
            uint32_t word;
        }base64;

#if BASE64_ENCODING
        static const std::string base64Chars = 
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";
#else
    #if BASE64_URL_ENCODING
        static const std::string base64Chars = 
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789-_";
    #endif
#endif
        
        std::string base64EnecodedString = "";
        uint16_t codeVerifierLength = arraySize;

        uint16_t leftOvers = codeVerifierLength % 3;
        codeVerifierLength = codeVerifierLength - leftOvers;
        uint8_t *pBytesPtr = &inputArray[0];
        for(uint32_t idx = 0; idx < codeVerifierLength; )
        {
            base64 b;
            uint32_t val = (*((uint32_t*)pBytesPtr)) & 0x00FFFFFF;
            b.word = ((val >> 16) & 0x0000FF) | (val & 0x00FF00) | ((val << 16) & 0xFF0000);
            // printf("0x%X 0x%X 0x%X 0x%X 0x%X\n", b.word, b.bases.a1, b.bases.a2, b.bases.a3, b.bases.a4);

            base64EnecodedString += base64Chars.at(b.bases.a4);
            base64EnecodedString += base64Chars.at(b.bases.a3);
            base64EnecodedString += base64Chars.at(b.bases.a2);
            base64EnecodedString += base64Chars.at(b.bases.a1);
            idx += 3;
            pBytesPtr += 3;
        }
        
        if(leftOvers)
        {
            uint8_t numCharsNeededToComplete = 3 - leftOvers;
            std::vector<uint8_t> finalStr;
            for (uint8_t i = 0; i < leftOvers; i++)
            {
                finalStr.push_back((inputArray[codeVerifierLength+i]));
                // printf("$$$$$$$[%c]\n", codeVerifier[codeVerifierLength+i]);
            }
            
            for (uint8_t i = 0; i < numCharsNeededToComplete; i++)
            {
                finalStr.push_back('\0');
            }
            const uint8_t *pBytesPtr = &finalStr[0];

            base64 b;
            uint32_t val = (*((uint32_t*)pBytesPtr)) & 0x00FFFFFF;
            b.word = ((val >> 16) & 0x0000FF) | (val & 0x00FF00) | ((val << 16) & 0xFF0000);
            // printf("0x%X 0x%X 0x%X 0x%X 0x%X\n", b.word, b.bases.a1, b.bases.a2, b.bases.a3, b.bases.a4);

            base64EnecodedString += base64Chars.at(b.bases.a4);
            base64EnecodedString += base64Chars.at(b.bases.a3);
            base64EnecodedString += base64Chars.at(b.bases.a2);
            base64EnecodedString += base64Chars.at(b.bases.a1);

#if BASE64_URL_ENCODING
            base64EnecodedString.resize(base64EnecodedString.size() - numCharsNeededToComplete);
#else
            uint8_t len = base64EnecodedString.size();
            for (uint8_t i = 0; i < numCharsNeededToComplete; i++)
            {
                base64EnecodedString[len - 1 - i] = '=';
            }
#endif
        }
        // printf("Base 64 URL encoded String [%s]\n", base64EnecodedString.c_str());
        // printf("0x%X 0x%X 0x%X 0x%X 0x%X\n", b.word, b.bases.a1, b.bases.a2, b.bases.a3, b.bases.a4);
        return base64EnecodedString;
    }

    uint32_t opRor(uint32_t input, uint8_t pos)
    {
        uint32_t shift_val = input >> pos;
        uint32_t rot_val = input << (32 - pos);
        return (shift_val | rot_val);
    }

    uint32_t opRsh(uint32_t input, uint8_t pos)
    {
        return input >> pos;
    }

    uint32_t opXor(uint32_t input1, uint32_t input2)
    {
        return (input1 ^ input2);
    }

    uint32_t opXor(uint32_t input1, uint32_t input2, uint32_t input3)
    {
        return (input1 ^ input2 ^ input3);
    }

    uint32_t opAdd(uint32_t input1, uint32_t input2, uint32_t input3, uint32_t input4)
    {
        uint64_t a = ((uint64_t)2<<(uint64_t)31);
        uint32_t b = (uint32_t)(a - (uint64_t)1);
        return (input1 + input2 + input3 + input4) %b;
    }

    uint32_t lSigmaZero(uint32_t input)
    {
        uint32_t o1 = opRor(input, 7);
        uint32_t o2 = opRor(input, 18);
        uint32_t o3 = opRsh(input, 3);

        return opXor(o1, o2, o3);
    }

    uint32_t lSigmaOne(uint32_t input)
    {
        uint32_t o1 = opRor(input, 17);
        uint32_t o2 = opRor(input, 19);
        uint32_t o3 = opRsh(input, 10);

        return opXor(o1, o2, o3);
    }

    uint32_t majority(uint32_t a, uint32_t b, uint32_t c)
    {
        return (a & b) ^ (a & c) ^ (b & c);
    }

    uint32_t uSigmaZero(uint32_t a)
    {
        uint32_t o1 = opRor(a, 2);
        uint32_t o2 = opRor(a, 13);
        uint32_t o3 = opRor(a, 22);

        return opXor(o1, o2, o3);
    }

    uint32_t choice(uint32_t e, uint32_t f, uint32_t g)
    {
        return (e & f) ^ (~e & g) ;
    }

    uint32_t uSigmaOne(uint32_t e)
    {
        uint32_t o1 = opRor(e, 6);
        uint32_t o2 = opRor(e, 11);
        uint32_t o3 = opRor(e, 25);

        return opXor(o1, o2, o3);
    }

    uint32_t temp2(uint32_t a, uint32_t b, uint32_t c)
    {
        return (uSigmaZero(a) + majority(a, b, c));
    }

    uint32_t temp1(uint32_t h, uint32_t e, uint32_t f, uint32_t g, uint32_t k, uint32_t w)
    {
        return (h + uSigmaOne(e) + choice(e, f, g) + k + w);
    }

    // https://stackoverflow.com/questions/21507678/reverse-bytes-for-64-bit-value
    uint64_t swapLong(uint64_t x)
    {
        x = (x & 0x00000000FFFFFFFF) << 32 | (x & 0xFFFFFFFF00000000) >> 32;
        x = (x & 0x0000FFFF0000FFFF) << 16 | (x & 0xFFFF0000FFFF0000) >> 16;
        x = (x & 0x00FF00FF00FF00FF) << 8  | (x & 0xFF00FF00FF00FF00) >> 8;
        return x;
    }

    void s_assert(bool cond)
    {
        if(!cond)
        {
            printf("[ERROR] Assert. Please check for error\n");
            exit(1);
        }
    }

    std::array<uint8_t, 32> sha256Encode(std::string input)
    {
        /*
            Note 1: All variables are 32 bit unsigned integers and addition is calculated modulo 2^32
            Note 2: For each round, there is one round constant k[i] and one entry in the message schedule array w[i], 0 ≤ i ≤ 63
            Note 3: The compression function uses 8 working variables, a through h
            Note 4: Big-endian convention is used when expressing the constants in this pseudocode,
                and when parsing message block data from bytes to words, for example,
                the first word of the input message "abc" after padding is 0x61626380

            Initialize hash values:
            (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
            h0 := 0x6a09e667
            h1 := 0xbb67ae85
            h2 := 0x3c6ef372
            h3 := 0xa54ff53a
            h4 := 0x510e527f
            h5 := 0x9b05688c
            h6 := 0x1f83d9ab
            h7 := 0x5be0cd19

            Initialize array of round constants:
            (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):
            k[0..63] :=
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

            Pre-processing (Padding):
            begin with the original message of length L bits
            append a single '1' bit
            append K '0' bits, where K is the minimum number >= 0 such that L + 1 + K + 64 is a multiple of 512
            append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 512 bits

            Process the message in successive 512-bit chunks:
            break message into 512-bit chunks
            for each chunk
                create a 64-entry message schedule array w[0..63] of 32-bit words
                (The initial values in w[0..63] don't matter, so many implementations zero them here)
                copy chunk into first 16 words w[0..15] of the message schedule array

                Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
                for i from 16 to 63
                    s0 := (w[i-15] rightrotate  7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift  3)
                    s1 := (w[i- 2] rightrotate 17) xor (w[i- 2] rightrotate 19) xor (w[i- 2] rightshift 10)
                    w[i] := w[i-16] + s0 + w[i-7] + s1

                Initialize working variables to current hash value:
                a := h0
                b := h1
                c := h2
                d := h3
                e := h4
                f := h5
                g := h6
                h := h7

                Compression function main loop:
                for i from 0 to 63
                    S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
                    ch := (e and f) xor ((not e) and g)
                    temp1 := h + S1 + ch + k[i] + w[i]
                    S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
                    maj := (a and b) xor (a and c) xor (b and c)
                    temp2 := S0 + maj
            
                    h := g
                    g := f
                    f := e
                    e := d + temp1
                    d := c
                    c := b
                    b := a
                    a := temp1 + temp2

                Add the compressed chunk to the current hash value:
                h0 := h0 + a
                h1 := h1 + b
                h2 := h2 + c
                h3 := h3 + d
                h4 := h4 + e
                h5 := h5 + f
                h6 := h6 + g
                h7 := h7 + h

            Produce the final hash value (big-endian):
            digest := hash := h0 append h1 append h2 append h3 append h4 append h5 append h6 append h7
        */

        uint32_t h0 = 0x6a09e667;
        uint32_t h1 = 0xbb67ae85;
        uint32_t h2 = 0x3c6ef372;
        uint32_t h3 = 0xa54ff53a;
        uint32_t h4 = 0x510e527f;
        uint32_t h5 = 0x9b05688c;
        uint32_t h6 = 0x1f83d9ab;
        uint32_t h7 = 0x5be0cd19;

        uint32_t k[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        // ******** START Input conditioning ********
        uint32_t _512bitchunkSize = ROUND_UP_DIV(((input.size()*BITS_IN_BYTE) + BITS_IN_BYTE), 512);
        uint32_t _chunkSizeInBytes = (SHA256_CHUNK_SIZE*_512bitchunkSize)/BITS_IN_BYTE;
        uint32_t _chunkSizeInWords = (SHA256_CHUNK_SIZE)/(BYTES_IN_U32*BITS_IN_BYTE);
        uint32_t inputLength = input.size();
        uint32_t numberOfBits = inputLength*8;

        // printf("Input String[%s] Strlen[%d] inputLenBits[%d]\n", input.c_str(), inputLength, numberOfBits);
        // Place the string in a array container
        std::vector<uint8_t>inputArr;
        inputArr.resize(_chunkSizeInBytes);
        // memset(inputArr, 0, sizeof(inputArr));
        uint16_t inputArrLen = 0;
        const uint8_t* pInputStringPtr = reinterpret_cast<const uint8_t*>(input.c_str());
        memcpy((uint8_t*)&inputArr[0], pInputStringPtr, inputLength);
        inputArrLen += inputLength;
        // Append a 1 at the end of the message
        inputArr[inputArrLen] = 0x80;
        inputArrLen += 1;
        // Add padding 0's to make 512bit chunks. Skip the last 64bits which will store the string length
        uint16_t paddingBytes = ((SHA256_CHUNK_SIZE*_512bitchunkSize) - (numberOfBits + BITS_IN_BYTE) - (BYTES_IN_U64*BITS_IN_BYTE))/BITS_IN_BYTE;
        inputArrLen += paddingBytes;

        uint64_t length = swapLong(inputLength*BITS_IN_BYTE);
        // printf("swapping all the bytes gives 0x%016llx 0x%016llx\n",(uint64_t)inputLength, (uint64_t)length);
        memcpy((uint8_t*)&inputArr[inputArrLen], (uint8_t*)&length, BYTES_IN_U64);
        inputArrLen += BYTES_IN_U64;
#if SHA_DEBUG_PRINT
        for(uint16_t i = 0; i < inputArrLen; i+=4)
        {
            printf("0x%02X 0x%02X 0x%02X 0x%02X\n", inputArr[i], inputArr[i+1], inputArr[i+2], inputArr[i+3]);
        }
#endif
        s_assert((inputArrLen*BITS_IN_BYTE) == (SHA256_CHUNK_SIZE*_512bitchunkSize));
        // ******** END Input conditioning ********

        uint32_t* pInputEntryPtr = (uint32_t*)&inputArr[0];

        for (uint32_t chunk = 0; chunk < _512bitchunkSize; chunk++)
        {
            // ******** START Message Schedule STAGE 1********
            // Create a message schedule of 64 32bit words
            uint32_t w[MESSAGE_SCHEUDLE_WORD_COUNT];
            memset(w, 0, sizeof(w));
            
            for (uint32_t i = 0; i < _chunkSizeInWords; i++)
            {
                uint32_t val = __bswap_32(*pInputEntryPtr);
                w[i] = val;
                pInputEntryPtr++;
            }
#if SHA_DEBUG_PRINT
            for (uint32_t i = 0; i < _chunkSizeInWords; i++)
            {
                printf("w%d 0x%08X\n", i, w[i]);
            }
#endif
            for (uint32_t i = 0; i < (MESSAGE_SCHEUDLE_WORD_COUNT - _chunkSizeInWords); i++)
            {
                uint32_t a = lSigmaZero(w[1+i]);
                uint32_t b = lSigmaOne(w[14+i]);
                uint32_t c = w[i];
                uint32_t d = w[9+i];

                w[16 + i] = opAdd(a, b, c, d);
            }
#if SHA_DEBUG_PRINT
            for (uint32_t i = 0; i < MESSAGE_SCHEUDLE_WORD_COUNT; i++)
            {
                printf("w%d 0x%08X\n", i, w[i]);
            }
#endif
            // ******** END Message Schedule STAGE 1********

            // ******** START Message Schedule STAGE 2********
            uint32_t a = h0;
            uint32_t b = h1;
            uint32_t c = h2;
            uint32_t d = h3;
            uint32_t e = h4;
            uint32_t f = h5;
            uint32_t g = h6;
            uint32_t h = h7;

            for (uint32_t i = 0; i < MESSAGE_SCHEUDLE_WORD_COUNT; i++)
            {

                uint32_t temp1Val = temp1(h, e, f, g, k[i], w[i]);
                uint32_t temp2Val = temp2(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + temp1Val;
                d = c;
                c = b;
                b = a;
                a = temp1Val + temp2Val;
            }
            
            h0 = h0 + a;
            h1 = h1 + b;
            h2 = h2 + c;
            h3 = h3 + d;
            h4 = h4 + e;
            h5 = h5 + f;
            h6 = h6 + g;
            h7 = h7 + h;
        }

        // char opBuf[1280];
        // memset(opBuf, 0, sizeof(opBuf));
        // sprintf(opBuf, "%08x%08x%08x%08x%08x%08x%08x%08x", h0, h1, h2, h3, h4, h5, h6, h7);

        // std::string ret;
        // ret += to_string_conv(h0);
        // ret += to_string_conv(h1);
        // ret += to_string_conv(h2);
        // ret += to_string_conv(h3);
        // ret += to_string_conv(h4);
        // ret += to_string_conv(h5);
        // ret += to_string_conv(h6);
        // ret += to_string_conv(h7);

        std::array<uint8_t, 32> m;
        array_filler_1(h0, m, 0, 0);
        array_filler_2(h0, m, 1, 0);
        array_filler_3(h0, m, 2, 0);
        array_filler_4(h0, m, 3, 0);

        array_filler_1(h1, m, 0, 4);
        array_filler_2(h1, m, 1, 4);
        array_filler_3(h1, m, 2, 4);
        array_filler_4(h1, m, 3, 4);

        array_filler_1(h2, m, 0, 8);
        array_filler_2(h2, m, 1, 8);
        array_filler_3(h2, m, 2, 8);
        array_filler_4(h2, m, 3, 8);

        array_filler_1(h3, m, 0, 12);
        array_filler_2(h3, m, 1, 12);
        array_filler_3(h3, m, 2, 12);
        array_filler_4(h3, m, 3, 12);

        array_filler_1(h4, m, 0, 16);
        array_filler_2(h4, m, 1, 16);
        array_filler_3(h4, m, 2, 16);
        array_filler_4(h4, m, 3, 16);

        array_filler_1(h5, m, 0, 20);
        array_filler_2(h5, m, 1, 20);
        array_filler_3(h5, m, 2, 20);
        array_filler_4(h5, m, 3, 20);

        array_filler_1(h6, m, 0, 24);
        array_filler_2(h6, m, 1, 24);
        array_filler_3(h6, m, 2, 24);
        array_filler_4(h6, m, 3, 24);

        array_filler_1(h7, m, 0, 28);
        array_filler_2(h7, m, 1, 28);
        array_filler_3(h7, m, 2, 28);
        array_filler_4(h7, m, 3, 28);
        
        // sprintf(opBuf, "%u%u%u%u%u%u%u%u", h0, h1, h2, h3, h4, h5, h6, h7);
        // printf("Helloa[%s]\n", opBuf);
        // ******** END Message Schedule STAGE 2********
        // std::string retVal (opBuf);
        return m;
    }  
};

#endif