/*
   Copyright 2023 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include "stream_codec.hpp"

#include <fstream>
#include <utility>

#include <boost/crc.hpp>
#include <boost/iostreams/device/back_inserter.hpp>
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/range/iterator_range.hpp>
#include <snappy.h>

#include <silkworm/core/common/base.hpp>

namespace silkworm::snappy {

//! Computation for CRC-32/ISCSI a.k.a. CRC-32/BASE91-C, CRC-32/CASTAGNOLI, CRC-32/INTERLAKEN, CRC-32C
//! https://reveng.sourceforge.io/crc-catalogue/17plus.htm
constexpr std::size_t kCrc32cBits{32};
constexpr std::size_t kCrc32cTruncPoly{0x1edc6f41};
constexpr std::size_t kCrc32cInitRem{0xffffffff};
constexpr std::size_t kCrc32cFinalXor{0xffffffff};
constexpr std::size_t kCrc32cReflectIn{true};
constexpr std::size_t kCrc32cReflectRem{true};

using crc32_castagnoli = boost::crc_optimal<
    kCrc32cBits,
    kCrc32cTruncPoly,
    kCrc32cInitRem,
    kCrc32cFinalXor,
    kCrc32cReflectIn,
    kCrc32cReflectRem>;

//! Compute CRC-32C as specified in RFC 3720
static uint32_t crc32c(std::string_view buffer) {
    crc32_castagnoli result;
    result.process_bytes(buffer.data(), buffer.size());
    return result.checksum();
}

//! Compute masked CRC-32C as specified in section 3 of https://github.com/google/snappy/blob/main/framing_format.txt
static uint32_t masked_crc32c(std::string_view buffer) {
    uint32_t c = crc32c(buffer);
    return uint32_t(c >> 15 | c << 17) + 0xa282ead8;
}

//! Compress
std::string compress(std::string_view input) {
    std::string output;
    output.resize(::snappy::MaxCompressedLength(input.size()));

    size_t compressed_length;
    ::snappy::RawCompress(input.data(), input.size(), output.data(), &compressed_length);
    output.resize(compressed_length);

    return output;
}

//! Decompress
std::string decompress(std::string_view input) {
    std::size_t uncompressed_length;
    bool ok = ::snappy::GetUncompressedLength(input.data(), input.size(), &uncompressed_length);
    if (!ok) throw std::runtime_error("invalid snappy uncompressed length");

    std::string output;
    output.resize(uncompressed_length);

    ok = ::snappy::RawUncompress(input.data(), input.size(), output.data());
    if (!ok) throw std::runtime_error("invalid snappy data");

    return output;
}

class FramingCompressor : public boost::iostreams::multichar_output_filter {
  public:
    template<typename Sink>
    std::streamsize write(Sink& dst, const char* data, std::streamsize n) {
        std::streamsize rest = n;

        while (rest != 0) {
            if (!stream_header_written_) {
                if (const bool ok = write_stream_header(dst); !ok) {
                    return n - rest;
                }
                stream_header_written_ = true;
            }

            const auto uncompressed_size = static_cast<std::size_t>(std::min(rest, kMaxBlockSize));
            const std::string_view uncompressed{data, uncompressed_size};
            const auto checksum = masked_crc32c(uncompressed);

            // Compress the buffer, discarding the result if the improvement isn't at least 12.5%
            const auto compressed = compress(uncompressed);

            uint8_t chunk_type;
            std::size_t chunk_length;
            if (compressed.length() > (uncompressed.length() - uncompressed.length() / 8)) {
                chunk_type = kChunkTypeUncompressedData;
                chunk_length = kChecksumSize + uncompressed.length();
            } else {
                chunk_type = kChunkTypeCompressedData;
                chunk_length = kChecksumSize + compressed.length();
            }

            // Fill in the chunk header that comes before the body
            if (const bool ok = write_chunk_header(dst, chunk_type, chunk_length, checksum); !ok) {
                return n - rest;
            }

            // Fill in the chunk body
            std::string_view chunk_body = chunk_type == kChunkTypeCompressedData ? compressed : uncompressed;
            if (const bool put_n_ok = write_n(dst, chunk_body); !put_n_ok) {
                return n - rest;
            }
            rest -= std::streamsize(uncompressed.length());
        }

        return n - rest;
    }

  private:
    template<typename Sink>
    static bool write_n(Sink& dst, std::string_view data) {
        for (const auto c : data) {
            if (const bool put_ok = boost::iostreams::put(dst, c); !put_ok) {
                return false;
            }
        }
        return true;
    }

    template<typename Sink>
    static bool write_stream_header(Sink& dst) {
        return write_n(dst, kMagicChunk);
    }

    template<typename Sink>
    static bool write_chunk_header(Sink& dst, uint8_t type, std::size_t length, uint32_t checksum) {
        if (const bool ok = boost::iostreams::put(dst, char(type)); !ok) return false;
        //if (const bool ok = boost::iostreams::put(s, char(length >> 0)); !ok) return false;
        //if (const bool ok = boost::iostreams::put(s, char(length >> 8)); !ok) return false;
        //if (const bool ok = boost::iostreams::put(s, char(length >> 16)); !ok) return false;
        std::string buffer1{3, '\0'};
        boost::endian::store_little_u24(reinterpret_cast<uint8_t*>(buffer1.data()), length);
        const auto count = boost::iostreams::write(dst, buffer1.data(), 3);
        if (count != 3) {
            return false;
        }
        std::string buffer{4, '\0'};
        boost::endian::store_little_u32(reinterpret_cast<uint8_t*>(buffer.data()), checksum);
        const auto write_count = boost::iostreams::write(dst, buffer.data(), kChecksumSize);
        if (write_count != kChecksumSize) {
            return false;
        }
        /*if (const bool ok = boost::iostreams::put(s, char(checksum >> 0)); !ok) return false;
        if (const bool ok = boost::iostreams::put(s, char(checksum >> 8)); !ok) return false;
        if (const bool ok = boost::iostreams::put(s, char(checksum >> 16)); !ok) return false;
        if (const bool ok = boost::iostreams::put(s, char(checksum >> 24)); !ok) return false;*/
        return true;
    }

    bool stream_header_written_{false};
};

class ChunkHeader {
  public:
    explicit ChunkHeader() : state_(kChunkType) { reset(); }

    void process(char c);
    void reset();

    [[nodiscard]] bool pristine() const { return state_ == kChunkType; }
    [[nodiscard]] bool done() const { return state_ == kDone; }
    [[nodiscard]] uint8_t chunk_type() const { return chunk_type_; }
    [[nodiscard]] uint32_t chunk_length() const { return chunk_length_; }

  private:
    enum State {
        kChunkType,
        kChunkLength,
        kDone
    } state_;

    uint8_t chunk_type_{0};
    uint32_t chunk_length_{0};
    uint32_t offset_{0};
};

void ChunkHeader::process(char c) {
    auto value = static_cast<uint8_t>(c);
    switch (state_) {
        case kChunkType: {
            chunk_type_ = value;
            state_ = kChunkLength;
            break;
        }
        case kChunkLength: {
            chunk_length_ += uint32_t(value) << (offset_ * 8);
            if (offset_ == 2) {
                offset_ = 0;
                state_ = kDone;
            } else {
                ++offset_;
            }
            break;
        }
        default: {
            SILKWORM_ASSERT(false);
        }
    }
}

void ChunkHeader::reset() {
    state_ = kChunkType;
    chunk_type_ = 0;
    chunk_length_ = 0;
    offset_ = 0;
}

class ChunkBody {
  public:
    explicit ChunkBody(ChunkHeader& header) : state_(kStart), header_(header) {
        encoded_buffer_.reserve(kMaxEncodedLenOfMaxBlockSize + kChecksumSize);
        decoded_buffer_.reserve(kMaxBlockSize);
        reset(header);
    }

    void process(char c);
    void reset(const ChunkHeader& header);

    [[nodiscard]] bool done() const { return state_ == kDone; }
    [[nodiscard]] std::string decoded_buffer() const { return decoded_buffer_; }

  private:
    enum State {
        kStart,
        kStreamIdentifier,
        kCompressedData,
        kUncompressedData,
        kPadding,
        kSkippableChunks,
        kDone
    } state_;

    ChunkHeader& header_;

    //! Compressed buffer containing one max block plus checksum at most (i.e. kMaxEncodedLenOfMaxBlockSize + kChecksumSize)
    std::string encoded_buffer_;

    //! Decoding buffer sized to keep one max block at most (i.e. kMaxBlockSize)
    std::string decoded_buffer_;
};

void ChunkBody::process(char c) {
    using namespace boost::endian;

    switch (state_) {
        case kStreamIdentifier: {
            // Section 4.1. Stream identifier (chunk type 0xff)
            encoded_buffer_.push_back(c);
            if (encoded_buffer_.size() == header_.chunk_length()) {
                if (encoded_buffer_ != kMagicBody) {
                    throw std::runtime_error{"invalid snappy: corrupted magic body"};
                }
                state_ = kDone;
            }
            break;
        }
        case kCompressedData: {
            // Section 4.2. Compressed data (chunk type 0x00)
            if (header_.chunk_length() < kChecksumSize) {
                throw std::runtime_error{"invalid snappy: corrupted compressed chunk"};
            }
            encoded_buffer_.push_back(c);
            if (encoded_buffer_.size() == header_.chunk_length()) {
                const auto checksum = load_little_u32(reinterpret_cast<const uint8_t*>(encoded_buffer_.data()));
                const auto data_length = header_.chunk_length() - kChecksumSize;
                auto uncompressed = decompress({encoded_buffer_.data() + kChecksumSize, data_length});
                if (uncompressed.length() > kMaxBlockSize) {
                    throw std::runtime_error{"invalid snappy: max block size exceeded in compressed chunk"};
                }
                if (masked_crc32c(uncompressed) != checksum) {
                    throw std::runtime_error{"invalid snappy: compressed chunk checksum error"};
                }
                decoded_buffer_ = std::move(uncompressed);
                state_ = kDone;
            }
            break;
        }
        case kUncompressedData: {
            // Section 4.3. Uncompressed data (chunk type 0x01)
            if (header_.chunk_length() < kChecksumSize) {
                throw std::runtime_error{"invalid snappy: corrupted uncompressed chunk"};
            }
            encoded_buffer_.push_back(c);
            if (encoded_buffer_.size() == header_.chunk_length()) {
                const auto checksum = load_little_u32(reinterpret_cast<const uint8_t*>(encoded_buffer_.data()));
                const auto data_length = header_.chunk_length() - kChecksumSize;
                if (data_length > kMaxBlockSize) {
                    throw std::runtime_error{"invalid snappy: max block size exceeded in uncompressed chunk"};
                }
                std::string_view uncompressed{encoded_buffer_.data() + kChecksumSize, data_length};
                if (masked_crc32c(uncompressed) != checksum) {
                    throw std::runtime_error{"invalid snappy: wrong checksum in uncompressed chunk"};
                }
                decoded_buffer_ = uncompressed;
                state_ = kDone;
            }
            break;
        }
        case kSkippableChunks: {
            // Section 4.6. Reserved skippable chunks (chunk types 0x80-0xfd)
            encoded_buffer_.push_back(c);
            if (encoded_buffer_.size() == header_.chunk_length()) {
                encoded_buffer_.clear();
                state_ = kDone;
            }
            break;
        }
        default: {
            SILKWORM_ASSERT(false);
        }
    }
}

void ChunkBody::reset(const ChunkHeader& header) {
    header_ = header;
    encoded_buffer_.clear();
    decoded_buffer_.clear();

    const uint8_t chunk_type = header_.chunk_type();
    switch (chunk_type) {
        case kChunkTypeStreamIdentifier: {
            state_ = kStreamIdentifier;
            break;
        }
        case kChunkTypeCompressedData: {
            state_ = kCompressedData;
            break;
        }
        case kChunkTypeUncompressedData: {
            state_ = kUncompressedData;
            break;
        }
        case kChunkTypePadding: {
            state_ = kPadding;
            break;
        }
        default: {
            if (chunk_type <= 0x7f) {
                // Section 4.5. Reserved unskippable chunks (chunk types 0x02-0x7f)
                throw std::runtime_error{"invalid snappy: reserved unskippable chunk"};
            }
            state_ = kSkippableChunks;
        }
    }
}

class FramingDecompressor : public boost::iostreams::multichar_input_filter {
  public:
    explicit FramingDecompressor() : state_{kStart}, magic_body_{magic_header_}, body_{header_} {}

    template<typename Source>
    std::streamsize read(Source& src, char* s, std::streamsize n) {
        using traits_type = boost::iostreams::char_traits<char_type>;
        std::streamsize result = 0;

        while (result < n && state_ != kDone) {
            switch (state_) {
                case kStart: {
                    state_ = kStreamHeader;
                    header_.reset();
                    break;
                }
                case kStreamHeader: {
                    const traits_type::int_type c = boost::iostreams::get(src);
                    if (traits_type::is_eof(c)) {
                        throw std::runtime_error{"invalid snappy: unexpected EOF in stream header"};
                    } else if (traits_type::would_block(c)) {
                        break;
                    }
                    magic_header_.process(c);
                    if (magic_header_.done()) {
                        if (magic_header_.chunk_type() != kChunkTypeStreamIdentifier) {
                            throw std::runtime_error{"invalid snappy: bad stream identifier"};
                        }
                        if (magic_header_.chunk_length() != kMagicBody.size()) {
                            throw std::runtime_error{"invalid snappy: wrong size for magic body"};
                        }
                        magic_body_.reset(magic_header_);
                        state_ = kStreamBody;
                    }
                    break;
                }
                case kStreamBody: {
                    const traits_type::int_type c = boost::iostreams::get(src);
                    if (traits_type::is_eof(c)) {
                        throw std::runtime_error{"invalid snappy: unexpected EOF in stream body"};
                    } else if (traits_type::would_block(c)) {
                        break;
                    }
                    magic_body_.process(c);
                    if (magic_body_.done()) {
                        magic_header_.reset();
                        magic_body_.reset(magic_header_);
                        state_ = kChunkHeader;
                    }
                    break;
                }
                case kChunkHeader: {
                    const traits_type::int_type c = boost::iostreams::get(src);
                    if (traits_type::is_eof(c)) {
                        if (header_.pristine()) {
                            state_ = kDone;
                            break;
                        } else {
                            throw std::runtime_error{"invalid snappy: unexpected EOF in chunk header"};
                        }
                    } else if (traits_type::would_block(c)) {
                        break;
                    }
                    header_.process(c);
                    if (header_.done()) {
                        body_.reset(header_);
                        state_ = kChunkBody;
                    }
                    break;
                }
                case kChunkBody: {
                    const traits_type::int_type c = boost::iostreams::get(src);
                    if (traits_type::is_eof(c)) {
                        throw std::runtime_error{"invalid snappy: unexpected EOF in chunk body"};
                    } else if (traits_type::would_block(c)) {
                        break;
                    }
                    body_.process(c);
                    result++;
                    if (body_.done()) {
                        if (header_.chunk_type() == kChunkTypeStreamIdentifier) {
                            result = -1;
                            header_.reset();
                            body_.reset(header_);
                            state_ = kChunkHeader;
                            break;
                        } else {
                            const auto body_buffer = body_.decoded_buffer();
                            traits_type::copy(s, body_buffer.data(), body_buffer.size());
                            //std::cout << "s  : " << to_hex(Bytes{reinterpret_cast<uint8_t*>(s), body_buffer.size()}) << "\n" << std::flush;
                            //std::cout << "sss: " << to_hex(Bytes{body_buffer.cbegin(), body_buffer.cend()}) << "\n" << std::flush;
                            result = static_cast<std::streamsize>(body_buffer.size());

                            header_.reset();
                            body_.reset(header_);
                            state_ = kChunkHeader;
                        }
                    }
                    break;
                }
                default: {
                    break;
                }
            }
        }

        return result != 0 || state_ != kDone ? result : -1;
    }

    template<typename Source>
    void close(Source& /*src*/) {  // NOLINT
        state_ = kStart;
    }

  private:
    template<typename Source>
    static std::streamsize read_n(Source& src, std::string& data, std::streamsize n) {
        using traits_type = boost::iostreams::char_traits<char_type>;

        std::streamsize result = 0;
        traits_type::int_type c = traits_type::good();
        while (result < n && !traits_type::is_eof(c)) {
            c = boost::iostreams::get(src);
            if (traits_type::would_block(c)) {
                return result;
            }
            if (traits_type::is_eof(c)) {
                return -1;
            }
            data.push_back(traits_type::to_char_type(c));
            result++;
        }
        SILKWORM_ASSERT(result == n);
        return result;
    }

    template<typename Source>
    static std::streamsize read_header(Source& s, std::string& header) {
        return read_n(s, header, std::streamsize(kChunkHeaderSize));
    }

    enum State {
        kStart,
        kStreamHeader,
        kStreamBody,
        kChunkHeader,
        kChunkBody,
        kDone
    } state_;

    ChunkHeader magic_header_;
    ChunkBody magic_body_;

    ChunkHeader header_;
    ChunkBody body_;
};

std::string framing_compress(std::string_view uncompressed) {
    if (uncompressed.empty()) {
        return kMagicChunk;
    }

    std::string compressed;
    compressed.reserve(kOutputBufferLength);

    boost::iostreams::filtering_ostream output;
    output.push(FramingCompressor{}, kMaxBlockSize);
    output.push(boost::iostreams::back_inserter(compressed));
    output.write(uncompressed.data(), static_cast<std::streamsize>(uncompressed.size()));
    output.flush();
    if (output.bad()) {
        throw std::runtime_error{std::string{"snappy framing compression error: "} + std::strerror(errno)};
    }

    return compressed;
}

std::string framing_uncompress(std::string_view compressed) {
    std::string uncompressed;
    uncompressed.reserve(kMaxBlockSize);

    boost::iostreams::filtering_istream input;
    input.push(FramingDecompressor{}, kMaxBlockSize);
    input.push(boost::make_iterator_range(compressed));
    // Read chars one-by-one: cannot use operator>> because it handles formatted input only (i.e. hard-coded break on space)
    using traits_type = boost::iostreams::char_traits<char>;
    while (true) {
        traits_type::int_type c = input.get();
        if (traits_type::is_eof(c)) {
            break;
        }
        uncompressed.push_back(traits_type::to_char_type(c));
    }
    if (input.bad()) {
        throw std::runtime_error{std::string{"snappy framing decompression error: "} + std::strerror(errno)};
    }

    //std::cout << "uncompressed.size()=" << uncompressed.size() << "\n" << std::flush;

    return uncompressed;
}

Bytes framing_compress(ByteView uncompressed) {
    std::string compressed = framing_compress({reinterpret_cast<const char*>(uncompressed.data()), uncompressed.size()});
    return {compressed.cbegin(), compressed.cend()};
}

Bytes framing_uncompress(ByteView compressed) {
    std::string uncompressed = framing_uncompress({reinterpret_cast<const char*>(compressed.data()), compressed.size()});
    return {uncompressed.cbegin(), uncompressed.cend()};
}

}  // namespace silkworm::snappy
