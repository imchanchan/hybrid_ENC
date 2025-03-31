#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string>
#include <vector>

const std::string publicKeyPEM = R"(-----BEGIN PUBLIC KEY-----

-----END PUBLIC KEY-----)";

const std::string privateKeyPEM = R"(-----BEGIN RSA PRIVATE KEY-----

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
