#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include "header.h"
#include <stdlib.h>
#include <time.h>

#include <iostream>  // std::cout, std::endl
#include <string>    // std::string



int padding = RSA_PKCS1_PADDING;
RSA* createRSA(unsigned char* key, int pub) {
    RSA* rsa = NULL;
    BIO* keybio = BIO_new_mem_buf(key, -1);

    if (keybio == NULL) {
        fprintf(stderr, "Failed to create key BIO\n");
        return NULL;
    }

    if (pub) {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, NULL, NULL, NULL);
    } else {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, NULL, NULL, NULL);
    }

    BIO_free(keybio);

    if (rsa == NULL) {
        fprintf(stderr, "Failed to create RSA structure\n");
    }

    return rsa;
}


int public_encrypt(unsigned char* data, int data_len, unsigned char* key, unsigned char* encrypted) {
    RSA* rsa = createRSA(key, 1);
    if (!rsa) return -1; 

    int result = RSA_public_encrypt(data_len, data, encrypted, rsa, padding);
    
    RSA_free(rsa); 
    return result;
}

int private_decrypt(unsigned char* enc_data, int data_len, unsigned char* key, unsigned char* decrypted) {
    RSA* rsa = createRSA(key, 0);
    if (!rsa) return -1;

    int result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, padding);
    
    RSA_free(rsa);
    return result;
}

void printLastError(const char* msg) {
    char err[130];  
    ERR_load_crypto_strings();
    ERR_error_string_n(ERR_get_error(), err, sizeof(err));  
    printf("%s ERROR: %s\n", msg, err);
    ERR_free_strings();
}

void hex_to_ascii(byte hex, char* str) {
    str[0] = ((hex >> 4) >= 0x0A) ? (hex >> 4) - 0x0A + 'a' : (hex >> 4) + '0';
    str[1] = ((hex & 0x0F) >= 0x0A) ? (hex & 0x0F) - 0x0A + 'a' : (hex & 0x0F) + '0';
    str[2] = '\0';
}

word* PASSWORD(word* output) {
    byte buffer = 0;
    byte input[64];

    int cnt = 0;
    for (int i = 0; i < 60; i++) {
        scanf("%c", &buffer);
        input[i] = buffer;
        if (buffer == '\n') {
            input[i] = '\0';
            cnt = i;
            break;
        }
    }

    srand(time(NULL));
    for (int i = 0; i < 4; i++) {
        input[cnt] = (byte)(rand() % 26 + 97);
        cnt++;
    }

    // SHA-1 기반 해싱 수행
    return hashing(input, 1000, output, cnt);
}


int main() {
    
    /* SHA-1: Password Hashing */
    word sessionkey[5];
    printf("비밀번호를 입력하세요. (60자 이하, 영문 소문자) PASSWORD : ");
    PASSWORD(sessionkey);

    /* AES: Key Expansion 및 파일 암호화 */
    byte AES_KEY[16];
    for (int i = 0; i < 4; i++) {
        PUTU32(AES_KEY + 4 * i, sessionkey[i]);
    }
    
    byte roundkey[11][16];
    KeyExpansion(AES_KEY, roundkey);
    file_enc(AES_KEY);

    /* RSA: 공개키/개인키 암호화 및 복호화 */
    char publicKey[] = "-----BEGIN PUBLIC KEY-----\n
    MIIFNTBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQxTRlsFlYUn9fVNmY
    FFleLAICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEPiSVyhpId1NuDK1
    +xQoUkYEggTQ+4J367x8Ez/gS0itVogkQ/oibvgL5DUQkXkK7UoF9jP2nnUFRch+
    q7KdBcOXxrFhKELiIf/TeEWsIfSFSHF9y+6cl3EiyEEaD/q8e/OVJXza3s67lHE9
    n9akGm8WAccKvef7JJ/SsJd98GoYwaFFm2mkKGAwIFXBjQD1oAaQMxv/VF0crzM5
    OwspdwwMlbOhrWeEQKTE6yvjA0jrzO7w1ZQdVveRwJVbDl9TYEKOLTQemCg3Ivsc
    B+46t9wN3nDz9CoeauqmpH2huV7Sr74AwlWkhVq2VhhWIuI0PLSPLjANVzZtlRS5
    PL6SHcuCrTd/KpUH+ucFIpT/82us2Vbgw3zqQihH4qxDPgLE2VBAnwt8rhfEx76U
    GkvKzMBe2VLcVuL5jdWWRGvERg/TwWi5QtKEMy5ZzBRUeNqbLQXEgBmLbX3yljxa
    uFYiHf3wUVUtJOL0KTkgKbNI3khX73YPqg1X6t4QOLRWa9mQvDxy68faWmh54o7o
    PbwViXopXPhwDbmPtqsswDLJwCQ9N5Jfq2xg0BF62wOzB8cmQBgv9aSZvgOQqDFE
    zQN/P8ATbgimywobPRd/qucJwgwzqtjGg4KffuOsRyY6S23RO48GaaiwfND7KGN2
    xPCAPuy7zxL4QpnUEhgQDmCMcBCbw4hdY5hQyh19JRrgkT7+OtUaST/OkKOOUA4a
    QoM+ITdqM6GpqwuT7XLFVuU54ATkGtuKh1MFVnWF+QOW84olZAD4M0n5IzjcQtzU
    reSi0VWUbpccPm4yM/abQ6hr9D/OZsVG2mXkV1Bpbd8Lk5U6BEV2ISMLTlpzb4vL
    XeS8ePHb75WF1DrjK8TN32YDnpm9dZ7+q0cU0NjdvHNyoswiYJx70dbR3m5cNw4k
    mQ3pF8NlXkRCXU3zSd3neosngPgl05vM42bEbP/3xxGdBHL1R7OSjRRxzwESZhx0
    o4Bk2VkzyhhBfoKga+EMhpod7QvgyRQ0asKVTsj59nkjukriZtJZgfe0aQqCNXr+
    sDuDL4hb9hjFHkabG0q0yQ+0BkBumuexXOBxzCRP3B8MLXMIiD6HojlFYxTb6VBk
    Nk2eLwX8548DeP+e7aAZ6/TxnyFWWeEq8d19WaYxXbRmjKiv6Bx/Eg3gYEkeu47t
    8IZ54hzeQ3L6qS3kMHGfeumQ7r9twbo8SjLeq692TpnTtqAWEnoT0w6O72ojewDo
    oIi7hvIN4Oq1nYI4WjNvu298IFwBXfLuRxgOgPx1FaX2GC6aVEtPY5D/47UbsHIL
    /Z06mVWceR8LasABNuAP2lfXHLzVJZ25OLB03Y3dfNmkPCcHqiKYyPqgG0j/PggR
    EfRg+YRyya9kdm0jtcFH1+kNfTXrN6CTy0v4xEpp/dN1bg64v7zrDIR18zQMxJNi
    Dg5f0PBlc18z4W9umsgqKGkdeeFSliDxAeFPhModDZZ7PXKh26+niIg2WYIwRWDJ
    g/41+W9kBtfotysRaAzW4A5iWJq4fLSjm96uTXIg82DQOGIkyOCdjSb1GsmAhv/k
    3qWLYmDrGyyeRyLUQFLtgBKX9DIr7BsHt0IOAWV/Gxh4o6kWpq9QIFDAai0D65/V
    P7QhWX2n4jYHIRcCBgmbQrKKXtRlusT2kXknJHXLVIorJO68LtD5AtU=
    -----END PUBLIC KEY-----\n";
    
    char privateKey[] = "-----BEGIN RSA PRIVATE KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAteri0/L0VdnjeNzi+22i
        LHHcc+O4k0PIaONB4xXnwYCzj+cU4yD3rVAUPl90+fv8Wd/cfspQ6kavvXIiJ9Oq
        AYni7bXPlbTP27LKFcLA3NGCDeVgtAcx+L5dS284Gl2e8QqomSvF1Bqc4qmuGL7K
        wfc6daXC0TwejoZkT8Vu3YU6AyBb48wNiiIQHxpEw+3hiF/Y7fN4Od/oSgjk6LQW
        QYMtfuR7z7SiFht3aIwrev9iBaQe0V97kc+OBjEYNhK7wUeBbeVvC8cotyS9chAZ
        HNNaXYVNmoFN8uqZwSHUv1+45T7okmaJ4OOSOY4Kx17stih5H81YKiIEz2XU/Z1m
        iwIDAQAB
        -----END RSA PRIVATE KEY-----\n";

    unsigned char encrypted[4098] = {0};
    unsigned char decrypted[4098] = {0};
    char plainText[] = "Hello, World!";
    
    /* 공개키 암호화 */
    int encrypted_length = public_encrypt((unsigned char*)plainText, strlen(plainText), (unsigned char*)publicKey, encrypted);
    if (encrypted_length == -1) {
        printLastError("Public Encrypt failed");
        return 1;
    }
    
    /* 개인키 복호화 */
    int decrypted_length = private_decrypt(encrypted, encrypted_length, (unsigned char*)privateKey, decrypted);
    if (decrypted_length == -1) {
        printLastError("Private Decrypt failed");
        return 1;
    }
    decrypted[decrypted_length] = '\0'; // 문자열 종료 처리

    /* 결과 출력 */
    printf("\n[RSA] 암호화 및 복호화 결과\n");
    printf("Original Text : %s\n", plainText);
    printf("Decrypted Text : %s\n", decrypted);
    
    return 0;
}
