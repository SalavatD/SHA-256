#include <iostream>

#include "SHA256.h"

int main() {

    SHA256 sha256;

    sha256.update("The quick brown fox jumps over the lazy dog");

    auto result = sha256.finalize(); // Return type: std::array<uint8_t, 32>

    for (const auto &item : result) {
        std::cout << std::hex << (uint32_t) item; // Output: d7a8fbb37d7809469ca9abcb082e4f8d5651e46d3cdb762d2d0bf37c9e592
    }
    return 0;
}
