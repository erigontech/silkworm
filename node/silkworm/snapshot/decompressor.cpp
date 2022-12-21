/*
   Copyright 2022 The Silkworm Authors

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

#include "decompressor.hpp"

#include <bitset>
#include <stdexcept>
#include <utility>
#include <vector>

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
#include <gsl/util>

#include <silkworm/common/assert.hpp>
#include <silkworm/common/endian.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/common/util.hpp>

namespace pb = google::protobuf::io;

namespace silkworm {

//! Size in bytes of metadata header fields in compressed file
constexpr std::size_t kWordsCountSize{sizeof(uint64_t)};
constexpr std::size_t kEmptyWordsCountSize{sizeof(uint64_t)};
constexpr std::size_t kDictionaryLengthSize{sizeof(uint64_t)};

//! Minimum compressed file size given the metadata header
constexpr std::size_t kMinimumFileSize = 32;

//! Maximum allowed depth in compressed file
constexpr std::size_t kMaxAllowedDepth = 2048;

DecodingTable::DecodingTable(std::size_t max_depth) : max_depth_(max_depth) {
    bit_length_ = max_depth_ > kMaxTableBitLength ? kMaxTableBitLength : max_depth_;
}

CodeWord::CodeWord() : CodeWord(0, 0, {}, nullptr, nullptr) {}

CodeWord::CodeWord(uint16_t code, uint8_t length, ByteView pattern)
    : CodeWord(code, length, pattern, nullptr, nullptr) {}

CodeWord::CodeWord(uint16_t code, uint8_t length, ByteView pattern, std::unique_ptr<PatternTable> table, CodeWord* next)
    : code_(code), code_length_(length), pattern_(pattern), table_(std::move(table)), next_(next) {}

void CodeWord::reset_content(uint16_t code, uint8_t length, ByteView pattern) {
    code_ = code;
    code_length_ = length;
    pattern_ = pattern;
    table_ = nullptr;
}

void CodeWord::set_next(CodeWord* next) {
    next_ = next;
}

std::ostream& operator<<(std::ostream& out, const PatternTable& pt) {
    out << "Pattern Table:\n";
    out << "bit length: " << pt.bit_length_ << "\n";
    out << std::setfill('0');
    const int bit_len = static_cast<int>(pt.bit_length_);
    for (std::size_t i{0}; i < pt.codewords_.size(); ++i) {
        const auto& cw = pt.codewords_[i];
        if (cw) {
            out << std::dec << std::setw(3) << i << " " << std::hex << std::setw(bit_len) << cw->code() << "\n";
        } else {
            out << std::dec << std::setw(3) << i << " NULL\n";
        }
    }
    out << std::dec;
    return out;
}

//! Build the table of word distances in range (0, 512) for each power of 2 in use except 2^0
//! @details The resulting matrix has distance steps equal to 2^i for each i in (0, 9) i.e.
//! 0 -> []
//! 1 -> [2 4 6 8 10 12 ... 508 510]
//! 2 -> [4 8 12 16 20 ... 504 508]
//! ...
//! 7 -> [128 256 384]
//! 8 -> [256]
//! 9 -> []
//! @return the word distances for power of 2
static PatternTable::WordDistances build_word_distances() {
    PatternTable::WordDistances word_distances{};
    for (std::size_t i{1}; i < PatternTable::kNumPowers; ++i) {
        std::vector<int> distances{};
        distances.reserve((std::size_t(1) << (PatternTable::kNumPowers - 1 - i)) - 1);
        for (int j{1 << i}; 0 < j && j < PatternTable::kMaxPower; j += (1 << i)) {
            distances.push_back(j);
        }
        word_distances[i] = std::move(distances);
    }
    return word_distances;
}

//! Initialize once and for all the word distances in the data for each power of 2
const PatternTable::WordDistances PatternTable::word_distances_{build_word_distances()};

//! Initialize condensed table threshold for bit length using default value
std::size_t PatternTable::condensed_table_bit_length_threshold_{kDefaultCondensedTableBitLengthThreshold};

void PatternTable::set_condensed_table_bit_length_threshold(std::size_t condensed_table_bit_length_threshold) {
    if (condensed_table_bit_length_threshold > kMaxTableBitLength) {
        throw std::invalid_argument{
            "bit length threshold for condensed tables is too big: " +
            std::to_string(condensed_table_bit_length_threshold) +
            " max allowed value is: " +
            std::to_string(kMaxTableBitLength)};
    }
    condensed_table_bit_length_threshold_ = condensed_table_bit_length_threshold;
}

PatternTable::PatternTable(std::size_t max_depth) : DecodingTable(max_depth) {
    if (bit_length_ <= condensed_table_bit_length_threshold_) {
        codewords_.resize(std::size_t(1) << bit_length_);
    }
}

std::size_t PatternTable::build_condensed(std::span<Pattern> patterns) {
    return build_condensed(patterns, max_depth_, 0, 0, 0);
}

std::size_t PatternTable::build_condensed(std::span<Pattern> patterns, uint64_t highest_depth, uint16_t code, int bits, uint64_t depth) {
    SILK_DEBUG << "#patterns: " << patterns.size() << " highest_depth: " << highest_depth << " code: " << code
               << " bits: " << std::bitset<CHAR_BIT>(static_cast<unsigned int>(bits)) << " depth: " << depth;
    if (patterns.empty()) {
        return 0;
    }
    const auto first_pattern = patterns.front();
    if (depth == first_pattern.depth) {
        insert_word(std::make_shared<CodeWord>(code, static_cast<uint8_t>(bits), first_pattern.value, nullptr, nullptr));
        return 1;
    }
    if (bits == kMaxTableBitLength) {
        auto new_table{std::make_unique<PatternTable>(highest_depth)};
        const auto last_cw = insert_word(std::make_shared<CodeWord>(code, 0, ByteView{}, std::move(new_table), nullptr));
        return last_cw->table()->build_condensed(patterns, highest_depth, 0, 0, depth);
    }
    const auto b0 = build_condensed(patterns, highest_depth - 1, code, bits + 1, depth + 1);
    return b0 + build_condensed(patterns.subspan(b0), highest_depth - 1, (1 << bits) | code, bits + 1, depth + 1);
}

CodeWord* PatternTable::insert_word(std::shared_ptr<CodeWord> codeword) {
    CodeWord* inserted{nullptr};
    if (bit_length_ <= condensed_table_bit_length_threshold_) {
        const auto code_step = 1 << codeword->code_length();
        const auto code_from = codeword->code();
        const auto code_to =
            bit_length_ != codeword->code_length() && codeword->code_length() > 0 ? code_from | 1 << bit_length_ : code_from + code_step;
        for (auto c{code_from}; c < code_to; c += code_step) {
            auto* cw = codewords_[c].get();
            if (cw == nullptr) {
                codewords_[c] = codeword;
                inserted = codewords_[c].get();
            } else {
                cw->reset_content(c, codeword->code_length(), codeword->pattern());
                inserted = cw;
            }
        }
    } else {
        codeword->set_next(nullptr);
        if (head_ == nullptr) {
            codewords_.push_back(std::move(codeword));
            head_ = codewords_.front().get();
            inserted = head_;
        } else {
            SILKWORM_ASSERT(!codewords_.empty());
            codewords_.push_back(std::move(codeword));
            inserted = codewords_.back().get();
        }
    }

    return inserted;
}

const CodeWord* PatternTable::search_condensed(uint16_t code) const {
    if (bit_length_ <= condensed_table_bit_length_threshold_) {
        return codeword(code);
    } else {
        CodeWord* previous{nullptr};
        for (auto* current = head_; current != nullptr; previous = current, current = current->next()) {
            if (current->code() == code) {
                if (previous != nullptr) {
                    previous->set_next(current->next());
                    current->set_next(head_);
                    head_ = current;
                }
                return current;
            }
            const auto distance = code - current->code();
            if ((distance & 0x1) != 0) {
                continue;
            }
            if (check_distance(current->code_length(), distance)) {
                if (previous != nullptr) {
                    previous->set_next(current->next());
                    current->set_next(head_);
                    head_ = current;
                }
                return current;
            }
        }
    }
    return nullptr;
}

bool PatternTable::check_distance(std::size_t power, int distance) {
    const auto& distances = PatternTable::word_distances_[power];
    auto it = std::find_if(distances.cbegin(), distances.cend(), [distance](const int d) {
        return d == distance;
    });
    return it != distances.cend();
}

PositionTable::PositionTable(std::size_t max_depth) : DecodingTable(max_depth) {
    positions_.resize(std::size_t(1) << bit_length_);
    lengths_.resize(std::size_t(1) << bit_length_);
    children_.resize(std::size_t(1) << bit_length_);
}

int PositionTable::build(std::span<Position> positions) {
    return build_tree(positions, max_depth_, 0, 0, 0);
}

int PositionTable::build_tree(std::span<Position> positions, uint64_t highest_depth, uint16_t code, int bits, uint64_t depth) {
    SILK_DEBUG << "build_tree #positions: " << positions.size() << " highest_depth: " << highest_depth << " code: " << code
               << " bits: " << std::bitset<CHAR_BIT>(static_cast<unsigned int>(bits)) << " depth: " << depth;
    if (positions.empty()) {
        return 0;
    }
    const auto& first_position = positions.front();
    if (depth == first_position.depth) {
        if (bit_length_ == static_cast<std::size_t>(bits)) {
            positions_[code] = first_position.value;
            lengths_[code] = static_cast<uint8_t>(bits);
            children_[code] = nullptr;
        } else {
            const auto code_step = 1 << bits;
            const auto code_from = code;
            const auto code_to = code_from | 1 << bit_length_;
            for (auto c{code_from}; c < code_to; c += code_step) {
                positions_[c] = first_position.value;
                lengths_[c] = static_cast<uint8_t>(bits);
                children_[c] = nullptr;
            }
        }
        return 1;
    }
    if (bits == kMaxTableBitLength) {
        auto child_table{std::make_unique<PositionTable>(highest_depth)};
        positions_[code] = 0;
        lengths_[code] = 0;
        children_[code] = std::move(child_table);
        return children_[code]->build_tree(positions, highest_depth, 0, 0, depth);
    }
    const int b0 = build_tree(positions, highest_depth - 1, code, bits + 1, depth + 1);
    return b0 + build_tree(positions.subspan(static_cast<std::size_t>(b0)), highest_depth - 1, (1 << bits) | code, bits + 1, depth + 1);
}

std::ostream& operator<<(std::ostream& out, const PositionTable& pt) {
    out << "Position Table:\n";
    out << "bit length: " << pt.bit_length_ << "\n";
    out << std::setfill('0');
    for (std::size_t i{0}; i < pt.positions_.size(); ++i) {
        const uint64_t position = pt.positions_[i];
        const uint64_t length = pt.lengths_[i];
        out << std::dec << std::setw(3) << i << " position: " << position << " length: " << length;
        const auto& child = pt.children_[i];
        if (child) {
            out << "child:\n\t\t" << *child << "\n";
        } else {
            out << " child: NULL\n";
        }
    }
    out << std::dec;
    return out;
}

Decompressor::Decompressor(std::filesystem::path compressed_path) : compressed_path_(std::move(compressed_path)) {}

Decompressor::~Decompressor() {
    close();
}

void Decompressor::open() {
    compressed_file_ = std::make_unique<MemoryMappedFile>(compressed_path_);
    if (compressed_file_->length() < kMinimumFileSize) {
        throw std::runtime_error("compressed file is too short: " + std::to_string(compressed_file_->length()));
    }

    const auto address = compressed_file_->address();

    compressed_file_->advise_sequential();

    // Read header from compressed file
    words_count_ = endian::load_big_u64(address);
    empty_words_count_ = endian::load_big_u64(address + kWordsCountSize);
    SILK_DEBUG << "Decompress words count: " << words_count_ << " empty words count: " << empty_words_count_;

    // Read patterns from compressed file
    const auto pattern_dict_length = endian::load_big_u64(address + kWordsCountSize + kEmptyWordsCountSize);
    SILK_INFO << "Decompress pattern dictionary length: " << pattern_dict_length;

    const std::size_t patterns_dict_offset{kWordsCountSize + kEmptyWordsCountSize + kDictionaryLengthSize};
    read_patterns(ByteView{address + patterns_dict_offset, pattern_dict_length});

    // Read positions from compressed file
    const auto position_dict_length = endian::load_big_u64(address + patterns_dict_offset + pattern_dict_length);
    SILK_INFO << "Decompress position dictionary length: " << position_dict_length;

    const std::size_t positions_dict_offset{patterns_dict_offset + pattern_dict_length + kDictionaryLengthSize};
    read_positions(ByteView{address + positions_dict_offset, position_dict_length});

    // Store the start offset and length of the data words
    words_start_ = address + positions_dict_offset + position_dict_length;
    words_length_ = compressed_file_->length() - (positions_dict_offset + position_dict_length);
    SILKWORM_ASSERT(address + compressed_file_->length() == words_start_ + words_length_);
    SILK_DEBUG << "Decompressor words start offset: " << (words_start_ - address) << " words length: " << words_length_
               << " total length: " << compressed_file_->length();

    compressed_file_->advise_random();
}

bool Decompressor::read_ahead(Decompressor::ReadAheadFunc fn) {
    if (!compressed_file_) {
        throw std::logic_error{"decompressor closed, call open first"};
    }
    compressed_file_->advise_sequential();
    auto _ = gsl::finally([&]() { compressed_file_->advise_random(); });
    Iterator it{this};
    return fn(it);
}

void Decompressor::close() {
    compressed_file_.reset();
}

void Decompressor::read_patterns(ByteView dict) {
    // Check the dictionary size to prevent overflow in pb::ArrayInputStream constructor
    if (dict.length() > std::numeric_limits<int>::max()) {
        throw std::runtime_error("dict is too long: " + std::to_string(dict.length()));
    }

    // Compression uses Google ProtocolBuffers encoding (see also Go "varint" encoding)
    pb::ArrayInputStream raw_input{dict.data(), static_cast<int>(dict.length())};
    pb::CodedInputStream coded_input{&raw_input};

    std::array<Pattern, kMaxTablePatterns> patterns{};
    uint64_t pattern_highest_depth{0};
    std::size_t pattern_count{0};
    for (; pattern_count < kMaxTablePatterns && coded_input.CurrentPosition() < raw_input.ByteCount(); ++pattern_count) {
        uint64_t pattern_depth{0};
        bool read_ok = coded_input.ReadVarint64(&pattern_depth);
        if (!read_ok) {
            throw std::runtime_error{"pattern dict is invalid: depth read failed at " + std::to_string(coded_input.CurrentPosition())};
        }
        SILK_DEBUG << "pattern depth: " << pattern_depth << " coded input position: " << coded_input.CurrentPosition();
        if (pattern_depth > kMaxAllowedDepth) {
            throw std::runtime_error{"pattern dict is invalid: pattern depth " + std::to_string(pattern_depth) +
                                     " is greater than max allowed: " + std::to_string(kMaxAllowedDepth)};
        }
        if (pattern_depth > pattern_highest_depth) {
            pattern_highest_depth = pattern_depth;
            SILK_DEBUG << "pattern highest depth: " << pattern_highest_depth;
        }

        uint64_t pattern_data_length{0};
        read_ok = coded_input.ReadVarint64(&pattern_data_length);
        if (!read_ok) {
            throw std::runtime_error{"pattern dict is invalid: length read failed at " + std::to_string(coded_input.CurrentPosition())};
        }
        if (pattern_data_length > std::numeric_limits<int>::max()) {
            throw std::runtime_error{"pattern data length is too long: " + std::to_string(pattern_data_length)};
        }
        SILK_DEBUG << "pattern data length: " << pattern_data_length << " coded input position: " << coded_input.CurrentPosition();

        ByteView pattern_data{dict.data() + coded_input.CurrentPosition(), pattern_data_length};
        read_ok = coded_input.Skip(static_cast<int>(pattern_data_length));
        if (!read_ok) {
            throw std::runtime_error{"pattern dict is invalid: data skip failed at " + std::to_string(coded_input.CurrentPosition())};
        }
        SILK_DEBUG << "count: " << pattern_count << " #pattern: " << pattern_data.size() << " coded input position: " << coded_input.CurrentPosition();

        patterns[pattern_count] = {pattern_depth, pattern_data};
    }
    if (coded_input.CurrentPosition() != raw_input.ByteCount()) {
        throw std::runtime_error{"pattern stream not exhausted: " + std::to_string(raw_input.ByteCount() - coded_input.CurrentPosition())};
    }

    SILK_INFO << "Pattern count: " << pattern_count << " highest depth: " << pattern_highest_depth;

    pattern_dict_ = std::make_unique<PatternTable>(pattern_highest_depth);
    if (dict.length() > 0) {
        pattern_dict_->build_condensed({patterns.begin(), pattern_count});
    }

    SILK_INFO << "#codewords: " << pattern_dict_->num_codewords();
    SILK_DEBUG << *pattern_dict_;
}

void Decompressor::read_positions(ByteView dict) {
    // Check the dictionary size to prevent overflow in pb::ArrayInputStream constructor
    if (dict.length() > std::numeric_limits<int>::max()) {
        throw std::runtime_error("position dict is too long: " + std::to_string(dict.length()));
    }

    // Compression uses Google ProtocolBuffers encoding (see also Go "varint" encoding)
    pb::ArrayInputStream raw_input{dict.data(), static_cast<int>(dict.length())};
    pb::CodedInputStream coded_input{&raw_input};

    std::array<Position, kMaxTablePositions> positions{};
    uint64_t position_highest_depth{0};
    std::size_t position_count{0};
    for (; position_count < kMaxTablePositions && coded_input.CurrentPosition() < raw_input.ByteCount(); ++position_count) {
        uint64_t position_depth{0};
        bool read_ok = coded_input.ReadVarint64(&position_depth);
        if (!read_ok) {
            throw std::runtime_error("position dict is invalid: depth read failed at " + std::to_string(coded_input.CurrentPosition()));
        }
        SILK_DEBUG << "position depth: " << position_depth << " coded input position: " << coded_input.CurrentPosition();
        if (position_depth > kMaxAllowedDepth) {
            throw std::runtime_error{"position dict is invalid: position depth " + std::to_string(position_depth) +
                                     " is greater than max allowed: " + std::to_string(kMaxAllowedDepth)};
        }
        if (position_depth > position_highest_depth) {
            position_highest_depth = position_depth;
            SILK_DEBUG << "position highest depth: " << position_highest_depth;
        }

        uint64_t position{0};
        read_ok = coded_input.ReadVarint64(&position);
        if (!read_ok) {
            throw std::runtime_error("position dict is invalid: position read failed at " + std::to_string(coded_input.CurrentPosition()));
        }
        if (position > std::numeric_limits<int>::max()) {
            throw std::runtime_error("position is too long: " + std::to_string(position));
        }
        SILK_DEBUG << "count: " << position_count << " position: " << position << " coded input position: " << coded_input.CurrentPosition();

        positions[position_count] = {position_depth, position};
    }
    if (coded_input.CurrentPosition() != raw_input.ByteCount()) {
        throw std::runtime_error{"position stream not exhausted: " + std::to_string(raw_input.ByteCount() - coded_input.CurrentPosition())};
    }

    SILK_INFO << "Position count: " << position_count << " highest depth: " << position_highest_depth;

    position_dict_ = std::make_unique<PositionTable>(position_highest_depth);
    if (dict.length() > 0) {
        position_dict_->build({positions.begin(), position_count});
    }

    SILK_INFO << "#positions: " << position_dict_->num_positions();
    SILK_DEBUG << *position_dict_;
}

Decompressor::Iterator::Iterator(const Decompressor* decoder) : decoder_(decoder) {}

ByteView Decompressor::Iterator::data() const {
    return ByteView{decoder_->words_start_, decoder_->words_length_};
}

uint64_t Decompressor::Iterator::next(Bytes& buffer) {
    const auto start_offset = word_offset_;

    uint64_t word_length = next_position(true);
    if (word_length == 0) {
        throw std::runtime_error{"invalid zero word length in: " + decoder_->compressed_path().string()};
    }
    --word_length;  // because when we create HT we do ++ (0 is terminator)
    SILK_DEBUG << "Iterator::next start_offset=" << start_offset << " word_length=" << word_length;
    if (word_length == 0) {
        if (bit_position_ > 0) {
            ++word_offset_;
            bit_position_ = 0;
        }
        return word_offset_;
    }

    // Track position into buffer where to insert part of the word
    std::size_t buffer_position = buffer.size();
    std::size_t last_uncovered = buffer.size();
    if (buffer.length() + word_length > buffer.capacity()) {
        buffer.reserve(buffer.length() + word_length);
    }
    buffer.resize(buffer.length() + word_length);
    SILK_DEBUG << "Iterator::next buffer resized to: " << buffer.length();

    // Fill in the patterns
    for (auto pos{next_position(false)}; pos != 0; pos = next_position(false)) {
        // Positions where to insert are encoded relative to one another
        buffer_position += pos - 1;
        const ByteView pattern = next_pattern();
        SILK_DEBUG << "Iterator::next data-from-patterns pos=" << pos << " pattern=" << to_hex(pattern);
        pattern.copy(buffer.data() + buffer_position, pattern.size(), 0);
    }
    if (bit_position_ > 0) {
        ++word_offset_;
    }
    uint64_t post_loop_offset = word_offset_;
    word_offset_ = start_offset;
    bit_position_ = 0;

    // Reset the iterator state
    (void)next_position(true);

    // Restore the beginning of buffer
    buffer_position = last_uncovered;

    // Fill in data which is not the patterns
    for (auto pos{next_position(false)}; pos != 0; pos = next_position(false)) {
        // Positions where to insert are encoded relative to one another
        buffer_position += pos - 1;
        if (buffer_position > last_uncovered) {
            uint64_t position_diff = buffer_position - last_uncovered;
            SILK_DEBUG << "Iterator::next other-data pos=" << pos << " last_uncovered=" << last_uncovered
                       << " buffer_position=" << buffer_position << " position_diff=" << position_diff
                       << " data=" << to_hex(ByteView{data().data() + post_loop_offset, position_diff});
            data().copy(buffer.data() + last_uncovered, position_diff, post_loop_offset);
            post_loop_offset += position_diff;
        }
        last_uncovered = buffer_position + next_pattern().size();
    }
    if (word_length > last_uncovered) {
        uint64_t position_diff = word_length - last_uncovered;
        SILK_DEBUG << "Iterator::next other-data last_uncovered=" << last_uncovered
                   << " buffer_position=" << buffer_position << " position_diff=" << position_diff
                   << " data=" << to_hex(ByteView{data().data() + post_loop_offset, position_diff});
        data().copy(buffer.data() + last_uncovered, position_diff, post_loop_offset);
        post_loop_offset += position_diff;
    }
    word_offset_ = post_loop_offset;
    bit_position_ = 0;
    SILK_DEBUG << "Iterator::next word_offset_=" << word_offset_;
    return post_loop_offset;
}

uint64_t Decompressor::Iterator::next_uncompressed(Bytes& buffer) {
    uint64_t word_length = next_position(true);
    if (word_length == 0) {
        throw std::runtime_error{"invalid zero word length in: " + decoder_->compressed_path().string()};
    }
    --word_length;  // because when we create HT we do ++ (0 is terminator)
    if (word_length == 0) {
        if (bit_position_ > 0) {
            ++word_offset_;
            bit_position_ = 0;
        }
        return word_offset_;
    }

    (void)next_position(false);
    if (bit_position_ > 0) {
        ++word_offset_;
        bit_position_ = 0;
    }
    uint64_t word_position = word_offset_;
    word_offset_ += word_length;
    buffer.resize(word_length);
    data().copy(buffer.data(), word_length, word_position);
    return word_offset_;
}

uint64_t Decompressor::Iterator::skip() {
    uint64_t word_length = next_position(true);
    if (word_length == 0) {
        throw std::runtime_error{"invalid zero word length in: " + decoder_->compressed_path().string()};
    }
    --word_length;  // because when we create HT we do ++ (0 is terminator)
    if (word_length == 0) {
        if (bit_position_ > 0) {
            ++word_offset_;
            bit_position_ = 0;
        }
        return word_offset_;
    }

    std::size_t uncovered_count{0};
    std::size_t buffer_position{0};
    std::size_t last_uncovered{0};
    for (auto pos{next_position(false)}; pos != 0; pos = next_position(false)) {
        // Positions where to insert are encoded relative to one another
        buffer_position += pos - 1;
        if (word_length < buffer_position) {
            throw std::logic_error{"likely index file is invalid: " + decoder_->compressed_path().string()};
        }
        if (buffer_position > last_uncovered) {
            uncovered_count += buffer_position - last_uncovered;
        }
        last_uncovered = buffer_position + next_pattern().size();
    }
    if (bit_position_ > 0) {
        ++word_offset_;
        bit_position_ = 0;
    }

    if (word_length > last_uncovered) {
        uncovered_count += word_length - last_uncovered;
    }
    word_offset_ += uncovered_count;

    return word_offset_;
}

uint64_t Decompressor::Iterator::skip_uncompressed() {
    uint64_t word_length = next_position(true);
    if (word_length == 0) {
        throw std::runtime_error{"invalid zero word length in: " + decoder_->compressed_path().string()};
    }
    --word_length;  // because when we create HT we do ++ (0 is terminator)
    if (word_length == 0) {
        if (bit_position_ > 0) {
            ++word_offset_;
            bit_position_ = 0;
        }
        return word_offset_;
    }

    (void)next_position(false);
    if (bit_position_ > 0) {
        ++word_offset_;
        bit_position_ = 0;
    }
    word_offset_ += word_length;
    return word_offset_;
}

void Decompressor::Iterator::reset(uint64_t data_offset) {
    word_offset_ = data_offset;
    bit_position_ = 0;
}

ByteView Decompressor::Iterator::next_pattern() {
    const PatternTable* table = decoder_->pattern_dict_.get();
    if (table->bit_length() == 0) {
        return table->codeword(0)->pattern();
    }
    uint8_t length{0};
    ByteView pattern{};
    while (length == 0) {
        const uint16_t code = next_code(table->bit_length());

        const auto* codeword{table->search_condensed(code)};
        if (codeword == nullptr) {
            const auto error_msg =
                "Unexpected missing codeword for code: " + std::to_string(code) +
                " in snapshot: " + decoder_->compressed_path().string();
            SILK_ERROR << error_msg;
            throw std::runtime_error{error_msg};
        }
        length = codeword->code_length();
        if (length == 0) {
            table = codeword->table();
            bit_position_ += 9;  // TODO(canepat) remove hard-coded value
        } else {
            bit_position_ += length;
            pattern = codeword->pattern();
        }
        word_offset_ += bit_position_ / CHAR_BIT;
        bit_position_ = bit_position_ % CHAR_BIT;
    }
    return pattern;
}

uint64_t Decompressor::Iterator::next_position(bool clean) {
    if (clean && bit_position_ > 0) {
        word_offset_++;
        bit_position_ = 0;
    }
    const PositionTable* table = decoder_->position_dict_.get();
    if (table->bit_length() == 0) {
        return table->position(0);
    }
    uint8_t length{0};
    uint64_t position{0};
    while (length == 0) {
        const uint16_t code = next_code(table->bit_length());
        length = table->length(code);
        if (length == 0) {
            table = table->child(code);
            bit_position_ += 9;  // TODO(canepat) remove hard-coded value
        } else {
            bit_position_ += length;
            position = table->position(code);
        }
        word_offset_ += bit_position_ / CHAR_BIT;
        bit_position_ = bit_position_ % CHAR_BIT;
    }
    return position;
}

uint16_t Decompressor::Iterator::next_code(std::size_t bit_length) {
    uint16_t code = static_cast<uint16_t>(decoder_->words_start_[word_offset_]) >> bit_position_;
    if (static_cast<std::size_t>(CHAR_BIT - bit_position_) < bit_length && word_offset_ + 1 < data_size()) {
        code |= decoder_->words_start_[word_offset_ + 1] << (CHAR_BIT - bit_position_);
    }
    code &= (1 << bit_length) - 1;
    return code;
}

}  // namespace silkworm
