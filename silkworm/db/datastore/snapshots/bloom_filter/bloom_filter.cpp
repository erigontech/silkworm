// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "bloom_filter.hpp"

#include <fstream>
#include <numbers>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string_view>

#include <openssl/evp.h>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/common/util.hpp>

namespace silkworm::snapshots::bloom_filter {

using namespace std::numbers;

//! The minimum Bloom filter bits count
static constexpr size_t kMinimumBitsCount = 2;

//! kRotation sets how much to rotate the hash on each filter iteration.
//! This is somewhat randomly set to a prime on the lower segment of 64.
static constexpr size_t kRotation = 17;

static constexpr size_t kRotationOf64 = 64 - kRotation;

//! The magic header used in serialization format for version v2
static constexpr std::string_view kMagicHeader{"\0\0\0\0\0\0\0\0v02\n"sv};

uint64_t BloomFilter::optimal_bits_count(uint64_t max_key_count, double p) {
    return static_cast<uint64_t>(std::ceil(-static_cast<double>(max_key_count) * std::log(p) / (ln2 * ln2)));
}

BloomFilter::BloomFilter(
    std::filesystem::path path,
    std::optional<KeyHasher> data_key_hasher)
    : BloomFilter{kMinimumBitsCount, new_random_keys()} {
    if (!std::filesystem::exists(path)) {
        throw std::runtime_error("index file " + path.filename().string() + " doesn't exist");
    }
    if (std::filesystem::file_size(path) == 0) {
        throw std::runtime_error("index file " + path.filename().string() + " is empty");
    }
    path_ = std::move(path);
    std::ifstream file_stream{path_, std::ios::in | std::ios::binary};
    file_stream.exceptions(std::ios::failbit | std::ios::badbit);
    file_stream >> *this;

    data_key_hasher_ = std::move(data_key_hasher);
}

BloomFilter::BloomFilter()
    : BloomFilter{kMinimumBitsCount, new_random_keys()} {}

BloomFilter::BloomFilter(uint64_t max_key_count, double p)
    : BloomFilter{optimal_bits_count(max_key_count, p), new_random_keys()} {}

BloomFilter::BloomFilter(uint64_t bits_count, KeyArray keys)
    : bits_count_(bits_count),
      keys_(keys),
      bits_((bits_count + 63) / 64, 0) {
    ensure_min_bits_count(bits_count);
}

void BloomFilter::add_hash(uint64_t hash) {
    for (size_t n = 0; n < kHardCodedK; ++n) {
        hash = ((hash << kRotation) | (hash >> kRotationOf64)) ^ keys_[n];
        const uint64_t i = hash % bits_count_;
        bits_[i >> 6] |= uint64_t{1} << (i & 0x3F);
    }
    ++inserted_count_;
}

bool BloomFilter::contains_hash(uint64_t hash) const {
    uint64_t r{1};
    for (size_t n = 0; n < kHardCodedK; ++n) {
        hash = ((hash << kRotation) | (hash >> kRotationOf64)) ^ keys_[n];
        const uint64_t i = hash % bits_count_;
        r &= (bits_[i >> 6] >> (i & 0x3F)) & uint64_t{1};
    }
    return r != 0;
}

bool BloomFilter::contains(ByteView data_key) const {
    return contains_hash(data_key_hasher_->hash(data_key));
}

void BloomFilter::ensure_min_bits_count(uint64_t bits_count) {
    if (bits_count < kMinimumBitsCount) {
        throw std::runtime_error{"number of bits must be >= " + std::to_string(kMinimumBitsCount) +
                                 " (was " + std::to_string(bits_count) + ")"};
    }
}

BloomFilter::KeyArray BloomFilter::new_random_keys() {
    // Reference Go implementation uses a CS-PRNG here for robustness (thus relying on OS-provided sources of randomness)
    // TODO(canepat) std::random_device is not guaranteed to be a CS-PRNG
    static std::mt19937_64 generator{std::random_device{}()};
    std::uniform_int_distribution<uint64_t> distribution;
    return {distribution(generator), distribution(generator), distribution(generator)};
}

//! SHA2-384 hash used for checksum
struct SHA384Hash {
    std::array<uint8_t, 48> buffer;
};

//! Decorator adding hashing support to the given input stream
class HashingInputStream {
  public:
    explicit HashingInputStream(std::istream& input_stream)
        : input_stream_(input_stream), md_ctx_{EVP_MD_CTX_create()} {
        input_stream_.exceptions(std::ios::failbit | std::ios::badbit);

        // Set up the digest context to use SHA384 message digest type
        if (const auto ec = EVP_DigestInit(md_ctx_, EVP_sha384()); !ec) {
            throw std::runtime_error{"EVP_DigestInit failed with code: " + std::to_string(ec)};
        }
    }
    ~HashingInputStream() {
        EVP_MD_CTX_destroy(md_ctx_);
    }

    SHA384Hash hash() {
        SHA384Hash sha384_md{};
        // Retrieve the computed digest value and its length from digest context
        unsigned int md_length = 0;
        if (const auto ec = EVP_DigestFinal(md_ctx_, sha384_md.buffer.data(), &md_length); !ec) {
            throw std::runtime_error{"EVP_DigestFinal failed with code: " + std::to_string(ec)};
        }
        if (md_length != sizeof(SHA384Hash)) {
            throw std::runtime_error{"EVP_DigestFinal unexpected MD length: " + std::to_string(md_length)};
        }
        return sha384_md;
    }

    void read(std::span<uint8_t> byte_span) {
        input_stream_.read(reinterpret_cast<char*>(byte_span.data()), static_cast<std::streamsize>(byte_span.size()));
        // Hash the read byte sequence into the digest context
        if (const auto ec = EVP_DigestUpdate(md_ctx_, byte_span.data(), byte_span.size()); !ec) {
            throw std::runtime_error{"EVP_DigestUpdate failed with code: " + std::to_string(ec)};
        }
    }

  private:
    //! The input stream to decorate
    std::istream& input_stream_;

    //! OpenSSL EnVeloPe Message Digest context
    EVP_MD_CTX* md_ctx_{nullptr};
};

std::istream& operator>>(std::istream& is, BloomFilter& filter) {
    HashingInputStream hashing_istream{is};

    // Read Magic Header byte sequence
    Bytes magic_buffer(kMagicHeader.size(), '\0');
    hashing_istream.read(magic_buffer);
    if (magic_buffer != string_view_to_byte_view(kMagicHeader)) {
        throw std::runtime_error{"incompatible version, wrong magic: " + to_hex(magic_buffer)};
    }

    // Read (K, N, M) triple as Little-Endian 64-bit unsigned integers
    Bytes uint64_buffer(sizeof(uint64_t), '\0');
    hashing_istream.read(uint64_buffer);
    const auto num_keys = endian::load_little_u64(uint64_buffer.data());
    if (num_keys != BloomFilter::kHardCodedK) {
        throw std::runtime_error{"keys must have length: " + std::to_string(BloomFilter::kHardCodedK)};
    }

    hashing_istream.read(uint64_buffer);
    const auto inserted_count = endian::load_little_u64(uint64_buffer.data());
    filter.inserted_count_ = inserted_count;

    hashing_istream.read(uint64_buffer);
    const auto bits_count = endian::load_little_u64(uint64_buffer.data());
    BloomFilter::ensure_min_bits_count(bits_count);
    filter.bits_count_ = bits_count;

    // Read the filter keys as Little-Endian 64-bit unsigned integers
    for (auto& key : filter.keys_) {
        hashing_istream.read(uint64_buffer);
        key = endian::load_little_u64(uint64_buffer.data());
    }

    // Read the filter bits as Little-Endian 64-bit unsigned integers
    filter.bits_.resize((bits_count + 63) / 64);
    for (auto& bit : filter.bits_) {
        hashing_istream.read(uint64_buffer);
        bit = endian::load_little_u64(uint64_buffer.data());
    }

    // Read the expected hash checksum from serialized data *not using* the hashing stream
    Bytes hash_buffer(sizeof(SHA384Hash), '\0');
    is.read(reinterpret_cast<char*>(hash_buffer.data()), static_cast<std::streamsize>(hash_buffer.size()));
    const auto sha384_hash = intx::le::unsafe::load<SHA384Hash>(hash_buffer.data());

    // Verify that the computed hash checksum does match the expected one
    const auto computed_hash = hashing_istream.hash();
    if (computed_hash.buffer != sha384_hash.buffer) {
        throw std::runtime_error{"hash mismatch: got=" + to_hex(computed_hash.buffer) + " expected=" + to_hex(sha384_hash.buffer) +
                                 " in file: " + filter.path().string()};
    }

    return is;
}

}  // namespace silkworm::snapshots::bloom_filter
