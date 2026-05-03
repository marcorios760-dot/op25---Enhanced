#include <iostream>
#include <cstdint>
#include <cstring>
#include <openssl/rc4.h>
#include <openssl/des.h>

const size_t TARGET_BYTES = 11;
const uint8_t IV_ADP[8] = {0x00};
const size_t KEYSTREAM_SKIP_ADP = 256;

void rc4_keystream(const uint8_t* key, size_t keylen, uint8_t* out, size_t len) {
    uint8_t S[256], T[256];
    int i, j, k;
    for (i = 0; i < 256; i++) S[i] = i;
    j = 0;
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keylen]) & 0xFF;
        std::swap(S[i], S[j]);
    }
    i = j = 0;
    for (k = 0; k < len; k++) {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        std::swap(S[i], S[j]);
        out[k] = S[(S[i] + S[j]) & 0xFF];
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <22-char_hex_ciphertext> --adp|--des\n";
        return 1;
    }

    std::string ciphertext_hex = argv[1];
    std::string cipher_type = argv[2];
    if (ciphertext_hex.length() != 22) {
        std::cerr << "Error: Ciphertext must be 22 hex characters (11 bytes).\n";
        return 1;
    }

    uint8_t ciphertext[TARGET_BYTES];
    for (size_t i = 0; i < TARGET_BYTES; i++) {
        std::string byte = ciphertext_hex.substr(i * 2, 2);
        ciphertext[i] = static_cast<uint8_t>(std::stoi(byte, nullptr, 16));
    }

    uint8_t rc4_key[13] = {0};
    uint8_t keystream[KEYSTREAM_SKIP_ADP + TARGET_BYTES] = {0};
    uint64_t total_keys = (cipher_type == "--adp") ? (1ULL << 40) : (1ULL << 56);

    for (uint64_t key_val = 0; key_val < total_keys; key_val++) {
        for (int i = 0; i < 5; i++) {
            rc4_key[4 - i] = (key_val >> (8 * i)) & 0xFF;
        }
        memcpy(rc4_key + 5, IV_ADP, 8);
        rc4_keystream(rc4_key, 13, keystream, KEYSTREAM_SKIP_ADP + TARGET_BYTES);
        if (memcmp(keystream + KEYSTREAM_SKIP_ADP, ciphertext, TARGET_BYTES) == 0) {
            std::cout << "0x";
            for (int i = 0; i < 5; i++) {
                std::cout << std::hex << (int)rc4_key[i];
            }
            std::cout << std::endl;
            return 0;
        }
        if (key_val % (1ULL << 28) == 0) {
            std::cerr << "\r[*] Progress: " << key_val << "/" << total_keys;
        }
    }
    std::cerr << "\n[-] Key not found.\n";
    return 1;
}