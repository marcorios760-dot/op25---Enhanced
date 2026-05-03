# P25 Key Extractor

This directory contains a CPU and optional GPU key recovery tool for P25 ADP and DES-OFB.

## Build

### Linux / macOS

```bash
mkdir -p build && cd build
cmake ..
make
```

If CUDA is available, the GPU target is built when `find_package(CUDAToolkit)` succeeds.

### Windows

```bash
mkdir build && cd build
cmake -G "Visual Studio 17 2022" -A x64 ..
cmake --build . --config Release
```

## Binaries

- `p25_keyextractor_cpu`: CPU tool for ADP and DES-OFB.
- `p25_keyextractor_gpu`: CUDA placeholder tool for DES-OFB (requires CUDA toolkit).

## Example

```bash
./p25_keyextractor_cpu 0123456789ABCDEF012345 --des --threads 24
```

## Notes

- The CUDA implementation is a template and requires a real DES-OFB kernel for practical GPU performance.
- DES-OFB brute-force on CPU is not practical for the full 56-bit keyspace.
