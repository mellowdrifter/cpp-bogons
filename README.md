# bogons (C++)

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Modern, header-only C++17/C++20 library for validating IP address, subnet prefix, and ASN [bogons](https://en.wikipedia.org/wiki/Bogon_filtering) with RFC descriptions.

Designed with `constexpr` and zero heap allocation for high-throughput packet processing (DPDK, Envoy, trading engines).

## Features

- **Header-Only & Modern C++17/C++20**: Drop-in `#include <bogons/bogons.hpp>`.
- **Compile-Time `constexpr` Evaluation**: Validates static IPs, ASNs, and prefixes directly at compile-time with zero runtime overhead.
- **Zero Dynamic Allocation**: Uses `std::string_view`, `std::array`, and `std::optional`.
- **IP Validation & Reasons**: Validates IPv4 (host-order `uint32_t`), IPv6 (`std::array<uint8_t, 16>`), or strings (`bogons::check_ip`).
- **ASN Validation & Parsing**: Validates 32-bit AS numbers with static RFC descriptions; supports `asplain` ("15169"), `AS`-prefixed ("AS15169"), and `asdot` ("1.0") notation (`bogons::parse_asn`, `bogons::check_asn`).
- **BGP Announcement Validation**: Enforces BGP routing limits (/8–/24 for IPv4, /16–/48 for IPv6) and rejects prefixes with host bits set (`bogons::valid_public_prefix`).
- **CMake Ready**: Supports CMake `add_subdirectory` and `find_package(bogons)`.

## Multi-Language Implementations

The `bogons` library is maintained with 100% feature parity, RFC attribution, and synchronized versioning across 6 languages:

| Language | Repository (GitHub) | Package Registry | Installation |
|---|---|---|---|
| **Go** | [mellowdrifter/bogons](https://github.com/mellowdrifter/bogons) | [pkg.go.dev](https://pkg.go.dev/github.com/mellowdrifter/bogons) | `go get github.com/mellowdrifter/bogons` |
| **Python** | [mellowdrifter/python-bogons](https://github.com/mellowdrifter/python-bogons) | [PyPI](https://pypi.org/project/bogons/) | `pip install bogons` |
| **Rust** | [mellowdrifter/rust-bogons](https://github.com/mellowdrifter/rust-bogons) | [crates.io](https://crates.io/crates/bogons) | `cargo add bogons` |
| **C** | [mellowdrifter/c-bogons](https://github.com/mellowdrifter/c-bogons) | [libbogons](https://github.com/mellowdrifter/c-bogons/releases) | Single-header / `make install` |
| **C++** | [mellowdrifter/cpp-bogons](https://github.com/mellowdrifter/cpp-bogons) | [CMake / Header-only](https://github.com/mellowdrifter/cpp-bogons/releases) | `#include <bogons/bogons.hpp>` |
| **TypeScript / JS** | [mellowdrifter/ts-bogons](https://github.com/mellowdrifter/ts-bogons) | [npm](https://www.npmjs.com/package/bogons) | `npm install bogons` |

## Installation

### Header-Only (Direct Copy)
Copy `include/bogons/bogons.hpp` to your project's include path.

### CMake FetchContent
```cmake
include(FetchContent)
FetchContent_Declare(
    bogons
    GIT_REPOSITORY https://github.com/mellowdrifter/cpp-bogons.git
    GIT_TAG        v1.4.1
)
FetchContent_MakeAvailable(bogons)
target_link_libraries(my_target PRIVATE bogons::bogons)
```

## Usage

```cpp
#include <bogons/bogons.hpp>
#include <iostream>

// Compile-time checks
static_assert(bogons::is_public_asn(15169));
static_assert(!bogons::is_public_asn(64512));
static_assert(bogons::is_public_ipv4(0x08080808U));

int main() {
    // Runtime IP validation
    auto res = bogons::check_ip("10.0.0.1");
    if (!res) {
        std::cout << "10.0.0.1 is a bogon: " << res.reason << "\n";
        // Output: 10.0.0.1 is a bogon: RFC 1918 (Private-Use)
    }

    // ASN parsing (supports decimal, AS prefix, and asdot)
    auto asn = bogons::parse_asn("AS1.0");
    if (asn) {
        std::cout << "Parsed ASN: " << *asn << "\n"; // 65536
    }

    // BGP Announcement validation
    bool valid = bogons::valid_public_prefix("8.8.8.0/24"); // true
    bool bad_host = bogons::valid_public_prefix("8.8.8.1/24"); // false (host bits set)

    return 0;
}
```

## License

Licensed under the Apache License, Version 2.0.
