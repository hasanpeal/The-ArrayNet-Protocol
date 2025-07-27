# The ArrayNet Protocol

A C implementation of a custom packet protocol for array serialization, deserialization, and integrity checking. This project demonstrates low-level data manipulation, bitwise operations, and robust testing practices.

## Features

- **Packet Serialization:** Convert integer arrays into network packets with custom headers and payloads.
- **Packet Deserialization:** Reconstruct arrays from received packets, handling fragmentation and corruption.
- **Checksum Calculation:** Ensure data integrity with a custom checksum algorithm.
- **Packet Inspection:** Print detailed packet contents for debugging and analysis.

## Project Structure

```
.
├── include/           # Public header(s)
│   └── hw1.h
├── src/               # Core implementation
│   ├── hw1.c
│   └── hw1_main.c
├── tests/
│   ├── include/       # Test argument headers
│   ├── src/           # Test drivers and GoogleTest suites
│   └── expected_outputs/ # Reference outputs for validation
├── CMakeLists.txt     # Build configuration
```

## Building

This project uses CMake:

```sh
cmake -S . -B build
cmake --build build
```

- The main executable: `hw1_main`
- All tests: `run_all_tests`
- Standalone Valgrind test drivers for memory checking

## Testing

Unit and integration tests are written using GoogleTest. Run all tests with:

```sh
./build/run_all_tests
```

Valgrind test drivers are also available for memory analysis.

## Example Usage

The main program (`hw1_main.c`) demonstrates how to print a packet’s contents.

