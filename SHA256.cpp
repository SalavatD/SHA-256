#include "SHA256.h"

void SHA256::update(const uint8_t *data, size_t size) {
    for (int i = 0; i < size; i++) {
        dataBlock[dataBlockSize++] = data[i];
        if (dataBlockSize == 64) {
            dataBlockSize = 0;
            countOfBits += 512;
            transform();
        }
    }
}

void SHA256::update(const std::string &data) {
    update(reinterpret_cast<const uint8_t *>(data.c_str()), data.size());
}

std::array<uint8_t, 32> SHA256::finalize() {
    std::array<uint8_t, 32> digest{};
    uint64_t count = dataBlockSize;
    const uint8_t end = dataBlockSize < 56 ? 56 : 64;
    dataBlock[count++] = 0x80;
    while (count < end) {
        dataBlock[count++] = 0x00;
    }
    if (dataBlockSize >= 56) {
        transform();
        dataBlock = std::array<uint8_t, 64>();
    }
    countOfBits += dataBlockSize * 8;
    dataBlock[56] = countOfBits >> 56;
    dataBlock[57] = countOfBits >> 48;
    dataBlock[58] = countOfBits >> 40;
    dataBlock[59] = countOfBits >> 32;
    dataBlock[60] = countOfBits >> 24;
    dataBlock[61] = countOfBits >> 16;
    dataBlock[62] = countOfBits >> 8;
    dataBlock[63] = countOfBits;
    transform();
    for (auto i = 0; i < 8; i++) {
        const auto value = uint32ToUint8(hash[i]);
        digest[0 + i * 4] = value[0];
        digest[1 + i * 4] = value[1];
        digest[2 + i * 4] = value[2];
        digest[3 + i * 4] = value[3];
    }
    return digest;
}

void SHA256::transform() {
    std::array<uint32_t, 64> w{};
    for (auto i = 0; i < 16; i++) {
        w[i] = uint8ToUint32({dataBlock[i * 4], dataBlock[i * 4 + 1], dataBlock[i * 4 + 2], dataBlock[i * 4 + 3]});
    }
    for (auto i = 16; i < 64; i++) {
        const auto s0 = gamma0(w[i - 15]);
        const auto s1 = gamma1(w[i - 2]);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    std::array<uint32_t, 8> h(hash);
    for (auto i = 0; i < 64; i++) {
        const auto s0 = sigma0(h[0]);
        const auto ma = majority(h[0], h[1], h[2]);
        const auto t2 = s0 + ma;
        const auto s1 = sigma1(h[4]);
        const auto ch = choose(h[4], h[5], h[6]);
        const auto t1 = h[7] + s1 + ch + k[i] + w[i];
        h[7] = h[6];
        h[6] = h[5];
        h[5] = h[4];
        h[4] = h[3] + t1;
        h[3] = h[2];
        h[2] = h[1];
        h[1] = h[0];
        h[0] = t1 + t2;
    }
    for (auto i = 0; i < 8; i++) {
        hash[i] += h[i];
    }
}

uint32_t SHA256::uint8ToUint32(const std::array<uint8_t, 4> &value) {
    uint32_t result = (value[0]) << 24 | (value[1]) << 16 | (value[2]) << 8 | (value[3]);
    return result;
}

std::array<uint8_t, 4> SHA256::uint32ToUint8(const uint32_t value) {
    std::array<uint8_t, 4> result{};
    for (int i = 0; i < 4; i++) {
        result[i] = value >> (24 - i * 8);
    }
    return result;
}
