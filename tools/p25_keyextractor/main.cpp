#include <iostream>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <iomanip>
#include <openssl/des.h>
#include <openssl/rc4.h>

const size_t TARGET_BYTES = 11;
const uint8_t IV_ADP[8] = {0x00};
const uint8_t IV_DES[8] = {0x00};
const size_t KEYSTREAM_SKIP_ADP = 256;

std::atomic<bool> key_found(false);
std::mutex cout_mutex;

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

void des_ofb_keystream(const uint8_t* key, const uint8_t* iv, uint8_t* out, size_t len) {
    DES_cblock ivec;
    DES_key_schedule schedule;
    std::memcpy(ivec, iv, 8);
    DES_set_key_unchecked((const_DES_cblock*)key, &schedule);

    unsigned char zeros[32] = {0};
    int num = 0;
    DES_ofb64_encrypt(zeros, out, static_cast<long>(len), &schedule, &ivec, &num);
}

void brute_force_adp(uint64_t start, uint64_t end, const uint8_t* ciphertext) {
    uint8_t rc4_key[13] = {0};
    uint8_t keystream[KEYSTREAM_SKIP_ADP + TARGET_BYTES] = {0};
    for (uint64_t key_val = start; key_val < end && !key_found; key_val++) {
        for (int i = 0; i < 5; i++)
            rc4_key[4 - i] = static_cast<uint8_t>((key_val >> (8 * i)) & 0xFF);
        std::memcpy(rc4_key + 5, IV_ADP, 8);
        rc4_keystream(rc4_key, 13, keystream, KEYSTREAM_SKIP_ADP + TARGET_BYTES);
        if (std::memcmp(keystream + KEYSTREAM_SKIP_ADP, ciphertext, TARGET_BYTES) == 0) {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << "0x";
            for (int i = 0; i < 5; i++) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(rc4_key[i]);
            }
            std::cout << std::endl;
            key_found = true;
            return;
        }
    }
}

void brute_force_des(uint64_t start, uint64_t end, const uint8_t* ciphertext) {
    uint8_t des_key[8] = {0};
    uint8_t keystream[16] = {0};
    for (uint64_t key_val = start; key_val < end && !key_found; key_val++) {
        for (int i = 0; i < 7; i++)
            des_key[6 - i] = static_cast<uint8_t>((key_val >> (8 * i)) & 0xFF);
        des_key[7] = 0;
        des_ofb_keystream(des_key, IV_DES, keystream, sizeof(keystream));
        if (std::memcmp(keystream, ciphertext, TARGET_BYTES) == 0) {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << "0x";
            for (int i = 0; i < 7; i++) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(des_key[i]);
            }
            std::cout << std::endl;
            key_found = true;
            return;
        }
    }
}

bool parse_hex(const char* hex, uint8_t* out, size_t len) {
    if (std::strlen(hex) != static_cast<int>(len * 2))
        return false;
    for (size_t i = 0; i < len; i++) {
        if (std::sscanf(hex + i * 2, "%2hhx", &out[i]) != 1)
            return false;
    }
    return true;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <22-char_hex_ciphertext> --adp|--des [--threads N]\n";
        return 1;
    }

    const char* ciphertext_hex = argv[1];
    const char* cipher_type = argv[2];
    int num_threads = 1;

    for (int i = 3; i < argc; i++) {
        if (std::strcmp(argv[i], "--threads") == 0 && (i + 1) < argc) {
            num_threads = std::atoi(argv[++i]);
            if (num_threads < 1) num_threads = 1;
        } else {
            std::cerr << "Unknown option: " << argv[i] << "\n";
            return 1;
        }
    }

    if (std::strcmp(cipher_type, "--adp") != 0 && std::strcmp(cipher_type, "--des") != 0) {
        std::cerr << "Error: Cipher type must be --adp or --des\n";
        return 1;
    }

    uint8_t ciphertext[TARGET_BYTES] = {0};
    if (!parse_hex(ciphertext_hex, ciphertext, TARGET_BYTES)) {
        std::cerr << "Error: Ciphertext must be 22 hex characters (11 bytes).\n";
        return 1;
    }

    if (num_threads > 64) {
        num_threads = 64;
    }

    uint64_t total_keys = (std::strcmp(cipher_type, "--adp") == 0) ? (1ULL << 40) : (1ULL << 56);
    uint64_t chunk = total_keys / static_cast<uint64_t>(num_threads);
    std::vector<std::thread> threads;
    threads.reserve(num_threads);

    for (int i = 0; i < num_threads; i++) {
        uint64_t start = static_cast<uint64_t>(i) * chunk;
        uint64_t end = (i == num_threads - 1) ? total_keys : (start + chunk);
        if (std::strcmp(cipher_type, "--adp") == 0) {
            threads.emplace_back(brute_force_adp, start, end, ciphertext);
        } else {
            threads.emplace_back(brute_force_des, start, end, ciphertext);
        }
    }

    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

    if (!key_found) {
        std::cerr << "[-] Key not found.\n";
        return 1;
    }

    return 0;
}
