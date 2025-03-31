#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string>
#include <vector>

const std::string publicKeyPEM = R"(-----BEGIN PUBLIC KEY-----
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
-----END PUBLIC KEY-----)";

const std::string privateKeyPEM = R"(-----BEGIN RSA PRIVATE KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAteri0/L0VdnjeNzi+22i
LHHcc+O4k0PIaONB4xXnwYCzj+cU4yD3rVAUPl90+fv8Wd/cfspQ6kavvXIiJ9Oq
AYni7bXPlbTP27LKFcLA3NGCDeVgtAcx+L5dS284Gl2e8QqomSvF1Bqc4qmuGL7K
wfc6daXC0TwejoZkT8Vu3YU6AyBb48wNiiIQHxpEw+3hiF/Y7fN4Od/oSgjk6LQW
QYMtfuR7z7SiFht3aIwrev9iBaQe0V97kc+OBjEYNhK7wUeBbeVvC8cotyS9chAZ
HNNaXYVNmoFN8uqZwSHUv1+45T7okmaJ4OOSOY4Kx17stih5H81YKiIEz2XU/Z1m
iwIDAQAB
-----END RSA PRIVATE KEY-----)";

RSA* createRSA(const std::string& key, bool isPublic) {
    BIO* keybio = BIO_new_mem_buf(key.c_str(), -1);
    if (!keybio) {
        std::cerr << "Failed to create key BIO" << std::endl;
        return nullptr;
    }

    RSA* rsa = nullptr;
    if (isPublic) {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, nullptr, nullptr);
    } else {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, nullptr, nullptr);
    }
    BIO_free(keybio);

    if (!rsa) {
        std::cerr << "Failed to create RSA" << std::endl;
    }
    return rsa;
}

std::vector<unsigned char> encryptWithPublicKey(RSA* rsa, const std::string& plaintext) {
    int rsaLen = RSA_size(rsa);
    std::vector<unsigned char> encrypted(rsaLen);

    int result = RSA_public_encrypt(plaintext.size(),
                                    reinterpret_cast<const unsigned char*>(plaintext.c_str()),
                                    encrypted.data(),
                                    rsa, RSA_PKCS1_OAEP_PADDING);

    if (result == -1) {
        std::cerr << "Encryption failed" << std::endl;
        return {};
    }
    return encrypted;
}

std::string decryptWithPrivateKey(RSA* rsa, const std::vector<unsigned char>& encrypted) {
    int rsaLen = RSA_size(rsa);
    std::vector<unsigned char> decrypted(rsaLen);

    int result = RSA_private_decrypt(encrypted.size(),
                                     encrypted.data(),
                                     decrypted.data(),
                                     rsa, RSA_PKCS1_OAEP_PADDING);

    if (result == -1) {
        std::cerr << "Decryption failed" << std::endl;
        return "";
    }
    return std::string(decrypted.begin(), decrypted.begin() + result);
}

int main() {
    std::string message = "Hello, RSA Encryption!";

    RSA* rsaPublic = createRSA(publicKeyPEM, true);
    RSA* rsaPrivate = createRSA(privateKeyPEM, false);

    if (!rsaPublic || !rsaPrivate) {
        return 1;
    }

    std::vector<unsigned char> encrypted = encryptWithPublicKey(rsaPublic, message);
    if (encrypted.empty()) {
        std::cerr << "Encryption error!" << std::endl;
        return 1;
    }

    std::string decrypted = decryptWithPrivateKey(rsaPrivate, encrypted);
    if (decrypted.empty()) {
        std::cerr << "Decryption error!" << std::endl;
        return 1;
    }

    std::cout << "Original Message: " << message << std::endl;
    std::cout << "Decrypted Message: " << decrypted << std::endl;

    RSA_free(rsaPublic);
    RSA_free(rsaPrivate);
    return 0;
}
