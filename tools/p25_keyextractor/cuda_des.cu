#include <iostream>
#include <cstdint>
#include <cuda_runtime.h>
#include <device_launch_parameters.h>

const size_t TARGET_BYTES = 11;
const uint8_t IV_DES[8] = {0x00};

__device__ bool compare_bytes(const uint8_t* a, const uint8_t* b, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        if (a[i] != b[i]) {
            return false;
        }
    }
    return true;
}

__global__ void des_ofb_brute_force(
    const uint8_t* ciphertext,
    uint8_t* found_key,
    bool* found,
    uint64_t start_key,
    uint64_t num_keys
) {
    uint64_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= num_keys || *found) return;

    uint64_t key_val = start_key + idx;
    uint8_t des_key[8] = {0};
    for (int i = 0; i < 7; i++) {
        des_key[6 - i] = static_cast<uint8_t>((key_val >> (8 * i)) & 0xFF);
    }

    // Placeholder: Replace with actual DES-OFB implementation.
    uint8_t keystream[16] = {0};

    if (compare_bytes(keystream, ciphertext, TARGET_BYTES)) {
        *found = true;
        for (int i = 0; i < 7; i++) {
            found_key[i] = des_key[i];
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <22-char_hex_ciphertext> --des\n";
        return 1;
    }

    uint8_t ciphertext[TARGET_BYTES];
    for (size_t i = 0; i < TARGET_BYTES; i++) {
        if (std::sscanf(argv[1] + i * 2, "%2hhx", &ciphertext[i]) != 1) {
            std::cerr << "Error: Ciphertext must be 22 hex characters (11 bytes).\n";
            return 1;
        }
    }

    uint8_t *d_ciphertext = nullptr;
    uint8_t *d_found_key = nullptr;
    bool *d_found = nullptr;

    cudaMalloc(&d_ciphertext, TARGET_BYTES);
    cudaMalloc(&d_found_key, 7);
    cudaMalloc(&d_found, sizeof(bool));

    bool found = false;
    cudaMemcpy(d_ciphertext, ciphertext, TARGET_BYTES, cudaMemcpyHostToDevice);
    cudaMemcpy(d_found, &found, sizeof(bool), cudaMemcpyHostToDevice);

    uint64_t total_keys = 1ULL << 56;
    uint64_t num_blocks = (total_keys + 255) / 256;
    if (num_blocks > 0xffffffffULL) {
        num_blocks = 0xffffffffULL;
    }

    des_ofb_brute_force<<<static_cast<unsigned int>(num_blocks), 256>>>(d_ciphertext, d_found_key, d_found, 0, total_keys);
    cudaDeviceSynchronize();

    cudaMemcpy(&found, d_found, sizeof(bool), cudaMemcpyDeviceToHost);
    if (found) {
        uint8_t found_key[7] = {0};
        cudaMemcpy(found_key, d_found_key, 7, cudaMemcpyDeviceToHost);
        std::cout << "0x";
        for (int i = 0; i < 7; i++) {
            std::printf("%02x", found_key[i]);
        }
        std::cout << std::endl;
    } else {
        std::cerr << "[-] Key not found.\n";
    }

    cudaFree(d_ciphertext);
    cudaFree(d_found_key);
    cudaFree(d_found);
    return 0;
}
