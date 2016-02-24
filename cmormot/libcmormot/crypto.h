#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace cmormot
{

using hash32 = std::uint32_t;

// compute the zlib/deflate crc32 hash value on a supplied buffer
hash32 crc32(hash32 aCrc32, const std::vector<uint8_t> & buf);

// compute the zlib/deflate crc32 hash value on a supplied ASCII-7 buffer
hash32 crc32ascii(hash32 aCrc32, const std::string & buf);

// internal buffer for SHA256 hashing
using sha256_buffer = std::array<hash32, 64>;

struct sha_hash
{
    hash32 A, B, C, D, E, F, G, H;
};

class sha256
{
public:
    // initialize SHA256 context for hashing
    sha256();

    // update the SHA256 context with some data
    void update(const std::vector<uint8_t> & buffer);

    // update the SHA256 context with 8 bit ascii data (e.g. UTF-8)
    void update(const std::string & ascii);

    // finalize and compute the resulting SHA256 hash Digest of all data
    // affected to update() method
    // - returns the data as Hexadecimal
    std::string finalize();

private:
    // working hash
    sha_hash hash_;

    // 64-bit message length
    size_t message_length_;

    // 
    sha256_buffer buffer_;
    size_t index_;

    void compress();
};

// compute SHA256 hexa digest of a supplied buffer
std::string sha256(const std::vector<uint8_t> & buf);

// compute SHA256 hexa digest of a supplied 8 bit ascii data (e.g. UTF-8)
std::string sha256(const std::string & buf);

}
