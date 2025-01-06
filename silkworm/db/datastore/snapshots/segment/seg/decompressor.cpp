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
#include <limits>
#include <stdexcept>
#include <utility>
#include <vector>

#include <gsl/util>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>

#include "common/varint.hpp"

namespace silkworm::snapshots::seg {

//! Size in bytes of metadata header fields in compressed file
static constexpr size_t kWordsCountSize{sizeof(uint64_t)};
static constexpr size_t kEmptyWordsCountSize{sizeof(uint64_t)};
static constexpr size_t kDictionaryLengthSize{sizeof(uint64_t)};

//! Minimum compressed file size given the metadata header
static constexpr size_t kMinimumFileSize = 32;

//! Maximum allowed depth in compressed file
static constexpr size_t kMaxAllowedDepth = 50;

DecodingTable::DecodingTable(size_t max_depth) : max_depth_(max_depth) {
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
    for (size_t i{0}; i < pt.codewords_.size(); ++i) {
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
    for (size_t i{1}; i < PatternTable::kNumPowers; ++i) {
        std::vector<int> distances{};
        distances.reserve((size_t{1} << (PatternTable::kNumPowers - 1 - i)) - 1);
        for (int j{1 << i}; 0 < j && j < PatternTable::kMaxPower; j += (1 << i)) {
            distances.push_back(j);
        }
        word_distances[i] = std::move(distances);
    }
    return word_distances;
}

//! Initialize once and for all the word distances in the data for each power of 2
const PatternTable::WordDistances PatternTable::kWordDistances{build_word_distances()};

//! Initialize condensed table threshold for bit length using default value
size_t PatternTable::condensed_table_bit_length_threshold_{kDefaultCondensedTableBitLengthThreshold};

void PatternTable::set_condensed_table_bit_length_threshold(size_t condensed_table_bit_length_threshold) {
    if (condensed_table_bit_length_threshold > kMaxTableBitLength) {
        throw std::invalid_argument{
            "bit length threshold for condensed tables is too big: " +
            std::to_string(condensed_table_bit_length_threshold) +
            " max allowed value is: " +
            std::to_string(kMaxTableBitLength)};
    }
    condensed_table_bit_length_threshold_ = condensed_table_bit_length_threshold;
}

PatternTable::PatternTable(size_t max_depth) : DecodingTable(max_depth) {
    if (bit_length_ <= condensed_table_bit_length_threshold_) {
        codewords_.resize(size_t{1} << bit_length_);
    }
}

size_t PatternTable::build_condensed(std::span<Pattern> patterns) {
    return build_condensed(patterns, max_depth_, 0, 0, 0);
}

size_t PatternTable::build_condensed(std::span<Pattern> patterns, uint64_t highest_depth, uint16_t code, int bits, uint64_t depth) {
    SILK_TRACE << "#patterns: " << patterns.size() << " highest_depth: " << highest_depth << " code: " << code
               << " bits: " << std::bitset<CHAR_BIT>(static_cast<unsigned int>(bits)) << " depth: " << depth;
    if (patterns.empty()) {
        return 0;
    }
    const auto first_pattern = patterns.front();
    if (depth == first_pattern.depth) {
        auto codeword = make_unique<CodeWord>(code, static_cast<uint8_t>(bits), first_pattern.value, nullptr, nullptr);
        codewords_list_.push_back(std::move(codeword));
        insert_word(codewords_list_.back().get());
        return 1;
    }
    if (bits == kMaxTableBitLength) {
        auto new_table{std::make_unique<PatternTable>(highest_depth)};
        auto codeword = make_unique<CodeWord>(code, 0, ByteView{}, std::move(new_table), nullptr);
        codewords_list_.push_back(std::move(codeword));
        const auto last_cw = insert_word(codewords_list_.back().get());
        return last_cw->table()->build_condensed(patterns, highest_depth, 0, 0, depth);
    }
    if (highest_depth == 0) {
        throw std::runtime_error("cannot build pattern tree: highest_depth reached zero");
    }
    const auto b0 = build_condensed(patterns, highest_depth - 1, code, bits + 1, depth + 1);
    return b0 + build_condensed(patterns.subspan(b0), highest_depth - 1, static_cast<uint16_t>((1 << bits) | code), bits + 1, depth + 1);
}

CodeWord* PatternTable::insert_word(CodeWord* codeword) {
    CodeWord* inserted{nullptr};
    if (bit_length_ <= condensed_table_bit_length_threshold_) {
        const size_t code_step = 1 << codeword->code_length();
        const size_t code_from = codeword->code();
        const size_t code_to =
            ((bit_length_ != codeword->code_length()) && (codeword->code_length() > 0))
                ? code_from | (1 << bit_length_)
                : code_from + code_step;
        for (size_t c = code_from; c < code_to; c += code_step) {
            auto cw = codewords_[c];
            if (cw == nullptr) {
                codewords_[c] = codeword;
                inserted = codewords_[c];
            } else {
                cw->reset_content(static_cast<uint16_t>(c), codeword->code_length(), codeword->pattern());
                inserted = cw;
            }
        }
    } else {
        codeword->set_next(nullptr);
        if (head_ == nullptr) {
            codewords_.push_back(codeword);
            head_ = codewords_.front();
            inserted = head_;
        } else {
            SILKWORM_ASSERT(!codewords_.empty());
            codewords_.push_back(codeword);
            inserted = codewords_.back();
        }
    }

    return inserted;
}

const CodeWord* PatternTable::search_condensed(uint16_t code) const {
    if (bit_length_ <= condensed_table_bit_length_threshold_) {
        return codeword(code);
    }
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
    return nullptr;
}

bool PatternTable::check_distance(size_t power, int distance) {
    const auto& distances = PatternTable::kWordDistances[power];
    auto it = std::find_if(distances.cbegin(), distances.cend(), [distance](const int d) {
        return d == distance;
    });
    return it != distances.cend();
}

PositionTable::PositionTable(size_t max_depth) : DecodingTable(max_depth) {
    positions_.resize(size_t{1} << bit_length_);
    lengths_.resize(size_t{1} << bit_length_);
    children_.resize(size_t{1} << bit_length_);
}

int PositionTable::build(std::span<Position> positions) {
    return build_tree(positions, max_depth_, 0, 0, 0);
}

int PositionTable::build_tree(std::span<Position> positions, uint64_t highest_depth, uint16_t code, int bits, uint64_t depth) {
    SILK_TRACE << "build_tree #positions: " << positions.size() << " highest_depth: " << highest_depth << " code: " << code
               << " bits: " << std::bitset<CHAR_BIT>(static_cast<unsigned int>(bits)) << " depth: " << depth;
    if (positions.empty()) {
        return 0;
    }
    const auto& first_position = positions.front();
    if (depth == first_position.depth) {
        if (bit_length_ == static_cast<size_t>(bits)) {
            positions_[code] = first_position.value;
            lengths_[code] = static_cast<uint8_t>(bits);
            children_[code] = nullptr;
        } else {
            const size_t code_step = 1 << bits;
            const size_t code_from = code;
            const size_t code_to = code_from | (1 << bit_length_);
            for (size_t c = code_from; c < code_to; c += code_step) {
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
    if (highest_depth == 0) {
        throw std::runtime_error("cannot build position tree: highest_depth reached zero");
    }
    const int b0 = build_tree(positions, highest_depth - 1, code, bits + 1, depth + 1);
    return b0 + build_tree(positions.subspan(static_cast<size_t>(b0)), highest_depth - 1, static_cast<uint16_t>((1 << bits) | code), bits + 1, depth + 1);
}

std::ostream& operator<<(std::ostream& out, const PositionTable& pt) {
    out << "Position Table:\n";
    out << "bit length: " << pt.bit_length_ << "\n";
    out << std::setfill('0');
    for (size_t i{0}; i < pt.positions_.size(); ++i) {
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

class Decompressor::ReadModeGuard {
  public:
    ReadModeGuard(
        const MemoryMappedFile& file,
        Decompressor::ReadMode new_mode,
        Decompressor::ReadMode old_mode)
        : file_(file),
          old_mode_(old_mode) {
        set_mode(new_mode);
    }
    virtual ~ReadModeGuard() {
        set_mode(old_mode_);
    }

  private:
    void set_mode(Decompressor::ReadMode mode) {
        switch (mode) {
            case ReadMode::kNormal:
                file_.advise_normal();
                break;
            case ReadMode::kRandom:
                file_.advise_random();
                break;
            case ReadMode::kSequential:
                file_.advise_sequential();
                break;
        }
    }

    const MemoryMappedFile& file_;
    Decompressor::ReadMode old_mode_;
};

Decompressor::Decompressor(
    std::filesystem::path compressed_path,
    std::optional<MemoryMappedRegion> compressed_region,
    CompressionKind compression_kind)
    : compressed_path_{std::move(compressed_path)},
      compressed_region_{compressed_region},
      compression_kind_{compression_kind},
      compressed_file_{compressed_path_, compressed_region_} {
    const auto compressed_file_size = compressed_file_.size();
    if (compressed_file_size < kMinimumFileSize) {
        throw std::runtime_error("compressed file is too short: " + std::to_string(compressed_file_size));
    }

    const auto address = compressed_file_.region().data();

    compressed_file_.advise_sequential();

    // Read header from compressed file
    words_count_ = endian::load_big_u64(address);
    empty_words_count_ = endian::load_big_u64(address + kWordsCountSize);
    SILK_TRACE << "Decompress words count: " << words_count_ << " empty words count: " << empty_words_count_;

    // Read patterns from compressed file
    const auto pattern_dict_length = endian::load_big_u64(address + kWordsCountSize + kEmptyWordsCountSize);
    SILK_TRACE << "Decompress pattern dictionary length: " << pattern_dict_length;
    if (pattern_dict_length > compressed_file_size - kMinimumFileSize) {
        throw std::runtime_error("invalid pattern_dict_length for compressed file size: " + std::to_string(compressed_file_size));
    }

    const size_t patterns_dict_offset{kWordsCountSize + kEmptyWordsCountSize + kDictionaryLengthSize};
    read_patterns(ByteView{address + patterns_dict_offset, pattern_dict_length});

    // Read positions from compressed file
    const auto position_dict_length = endian::load_big_u64(address + patterns_dict_offset + pattern_dict_length);
    SILK_TRACE << "Decompress position dictionary length: " << position_dict_length;
    if (position_dict_length > compressed_file_size - pattern_dict_length - kMinimumFileSize) {
        throw std::runtime_error("invalid position_dict_length for compressed file size: " + std::to_string(compressed_file_size));
    }

    const size_t positions_dict_offset{patterns_dict_offset + pattern_dict_length + kDictionaryLengthSize};
    read_positions(ByteView{address + positions_dict_offset, position_dict_length});

    // Store the start offset and length of the data words
    words_start_ = address + positions_dict_offset + position_dict_length;
    words_length_ = compressed_file_size - (positions_dict_offset + position_dict_length);
    SILKWORM_ASSERT(address + compressed_file_size == words_start_ + words_length_);
    SILK_TRACE << "Decompressor words start offset: " << (words_start_ - address) << " words length: " << words_length_
               << " total size: " << compressed_file_size;

    compressed_file_.advise_random();
}

Decompressor::Iterator Decompressor::begin() const {
    auto read_mode_guard = std::make_shared<ReadModeGuard>(compressed_file_, ReadMode::kSequential, ReadMode::kRandom);
    Iterator it{this, std::move(read_mode_guard)};
    if (it.has_next()) {
        ++it;
        return it;
    }
    return end();
}

Decompressor::Iterator Decompressor::seek(uint64_t offset, ByteView prefix) const {
    SILK_TRACE << "Decompressor::seek offset: " << offset;
    Iterator it = make_iterator();
    it.reset(offset);
    if (!it.has_next()) {
        return end();
    }

    if (!prefix.empty() && !it.has_prefix(prefix)) {
        return end();
    }

    try {
        ++it;
        return it;
    } catch (const std::runtime_error& re) {
        SILK_WARN << "Decompressor::seek invalid offset: " << offset << " what: " << re.what();
        return end();
    }
}

void Decompressor::read_patterns(ByteView dict) {
    ByteView raw_input = dict;
    std::vector<Pattern> patterns;
    patterns.reserve(kMaxTablePatterns);
    uint64_t pattern_highest_depth{0};
    auto current_position = [&]() -> size_t { return dict.size() - raw_input.size(); };

    while (!raw_input.empty()) {
        auto pattern_depth_opt = varint::decode(raw_input);
        if (!pattern_depth_opt) {
            throw std::runtime_error{"pattern dict is invalid: depth read failed at " + std::to_string(current_position())};
        }
        uint64_t pattern_depth = pattern_depth_opt.value();
        if (pattern_depth > kMaxAllowedDepth) {
            throw std::runtime_error{"pattern dict is invalid: pattern depth " + std::to_string(pattern_depth) +
                                     " is greater than max allowed: " + std::to_string(kMaxAllowedDepth)};
        }
        SILK_TRACE << "pattern depth: " << pattern_depth << " coded input position: " << current_position();

        if (pattern_depth > pattern_highest_depth) {
            pattern_highest_depth = pattern_depth;
            SILK_TRACE << "pattern highest depth: " << pattern_highest_depth;
        }

        auto pattern_data_length_opt = varint::decode(raw_input);
        if (!pattern_data_length_opt) {
            throw std::runtime_error{"pattern dict is invalid: length read failed at " + std::to_string(current_position())};
        }
        uint64_t pattern_data_length = pattern_data_length_opt.value();
        if (pattern_data_length > std::numeric_limits<int>::max()) {
            throw std::runtime_error{"pattern data length is too long: " + std::to_string(pattern_data_length)};
        }
        SILK_TRACE << "pattern data length: " << pattern_data_length << " coded input position: " << current_position();

        if (raw_input.size() < pattern_data_length) {
            throw std::runtime_error{"pattern dict is invalid: data skip failed at " + std::to_string(current_position())};
        }
        ByteView pattern_data{raw_input.data(), pattern_data_length};
        raw_input.remove_prefix(pattern_data_length);
        SILK_TRACE << "count: " << patterns.size() << " data size: " << pattern_data.size() << " coded input position: " << current_position();

        patterns.emplace_back(Pattern{pattern_depth, pattern_data});
    }

    SILK_TRACE << "Pattern count: " << patterns.size() << " highest depth: " << pattern_highest_depth;

    pattern_dict_ = std::make_unique<PatternTable>(pattern_highest_depth);
    if (!dict.empty()) {
        pattern_dict_->build_condensed({patterns.data(), patterns.size()});
    }

    SILK_TRACE << "#codewords: " << pattern_dict_->num_codewords();
    SILK_TRACE << *pattern_dict_;
}

void Decompressor::read_positions(ByteView dict) {
    ByteView raw_input = dict;
    std::vector<Position> positions;
    positions.reserve(kMaxTablePositions);
    uint64_t position_highest_depth{0};
    auto current_position = [&]() -> size_t { return dict.size() - raw_input.size(); };

    while (!raw_input.empty()) {
        auto position_depth_opt = varint::decode(raw_input);
        if (!position_depth_opt) {
            throw std::runtime_error("position dict is invalid: depth read failed at " + std::to_string(current_position()));
        }
        uint64_t position_depth = position_depth_opt.value();
        if (position_depth > kMaxAllowedDepth) {
            throw std::runtime_error{"position dict is invalid: position depth " + std::to_string(position_depth) +
                                     " is greater than max allowed: " + std::to_string(kMaxAllowedDepth)};
        }
        SILK_TRACE << "position depth: " << position_depth << " coded input position: " << current_position();

        if (position_depth > position_highest_depth) {
            position_highest_depth = position_depth;
            SILK_TRACE << "position highest depth: " << position_highest_depth;
        }

        auto position_opt = varint::decode(raw_input);
        if (!position_opt) {
            throw std::runtime_error("position dict is invalid: position read failed at " + std::to_string(current_position()));
        }
        uint64_t position = position_opt.value();
        if (position > std::numeric_limits<int>::max()) {
            throw std::runtime_error("position is too long: " + std::to_string(position));
        }
        SILK_TRACE << "count: " << positions.size() << " position: " << position << " coded input position: " << current_position();

        positions.emplace_back(Position{position_depth, position});
    }

    SILK_TRACE << "Position count: " << positions.size() << " highest depth: " << position_highest_depth;

    position_dict_ = std::make_unique<PositionTable>(position_highest_depth);
    if (!dict.empty()) {
        position_dict_->build({positions.data(), positions.size()});
    }

    SILK_TRACE << "#positions: " << position_dict_->num_positions();
    SILK_TRACE << *position_dict_;
}

Decompressor::Iterator::Iterator(
    const Decompressor* decoder,
    std::shared_ptr<ReadModeGuard> read_mode_guard)
    : decoder_(decoder),
      read_mode_guard_(std::move(read_mode_guard)) {}

ByteView Decompressor::Iterator::data() const {
    return ByteView{decoder_->words_start_, decoder_->words_length_};
}

bool Decompressor::Iterator::has_prefix(ByteView prefix) {
    const auto prefix_size{prefix.size()};

    const auto start_offset = word_offset_;
    [[maybe_unused]] auto _ = gsl::finally([&]() { word_offset_ = start_offset; bit_position_ = 0; });

    uint64_t next_data_position = next_position(true);
    if (next_data_position == 0) {
        throw std::runtime_error{"invalid zero next position in: " + decoder_->compressed_filename()};
    }
    const auto word_length = --next_data_position;  // because when we create HT we do ++ (0 is terminator)
    SILK_TRACE << "Iterator::has_prefix start_offset=" << start_offset << " word_length=" << word_length;
    if (word_length == 0 || word_length < prefix_size) {
        if (bit_position_ > 0) {
            ++word_offset_;
            bit_position_ = 0;
        }
        return prefix_size == word_length;
    }

    // First pass: we only check the patterns. Only run this loop as far as prefix goes, no need to go any further
    size_t buffer_position{0};
    for (auto pos{next_position(false)}; pos != 0; pos = next_position(false)) {
        // Positions where to insert patterns are encoded relative to one another
        buffer_position += pos - 1;
        const ByteView pattern = next_pattern();
        SILK_TRACE << "Iterator::has_prefix data-from-patterns pos=" << pos << " pattern=" << to_hex(pattern);
        const auto comparison_size{std::min(prefix_size - buffer_position, pattern.size())};
        if (buffer_position < prefix_size) {
            if (prefix.substr(buffer_position, comparison_size) != pattern.substr(0, comparison_size)) {
                return false;
            }
        }
    }
    if (bit_position_ > 0) {
        ++word_offset_;
        bit_position_ = 0;
    }
    uint64_t post_loop_offset = word_offset_;
    word_offset_ = start_offset;
    bit_position_ = 0;

    // Reset the iterator state
    (void)next_position(true);

    // Second pass: we check spaces not covered by the patterns
    size_t last_uncovered{0};
    buffer_position = 0;
    for (auto pos{next_position(false)}; pos != 0 && last_uncovered < prefix_size; pos = next_position(false)) {
        // Positions where to insert patterns are encoded relative to one another
        buffer_position += pos - 1;
        if (buffer_position > last_uncovered) {
            const size_t position_diff = buffer_position - last_uncovered;
            SILK_TRACE << "Iterator::has_prefix other-data pos=" << pos << " last_uncovered=" << last_uncovered
                       << " buffer_position=" << buffer_position << " position_diff=" << position_diff
                       << " data=" << to_hex(ByteView{data().data() + post_loop_offset, position_diff});
            const auto comparison_size{std::min(prefix_size - last_uncovered, position_diff)};
            if (prefix.substr(last_uncovered, comparison_size) != data().substr(post_loop_offset, comparison_size)) {
                return false;
            }
            post_loop_offset += position_diff;
        }
        last_uncovered = buffer_position + next_pattern().size();
    }
    if (prefix_size > last_uncovered && word_length > last_uncovered) {
        const size_t position_diff = word_length - last_uncovered;
        SILK_TRACE << "Iterator::has_prefix other-data last_uncovered=" << last_uncovered
                   << " buffer_position=" << buffer_position << " position_diff=" << position_diff
                   << " data=" << to_hex(ByteView{data().data() + post_loop_offset, position_diff});
        const auto comparison_size{prefix_size < word_length ? prefix_size - last_uncovered : position_diff};
        if (prefix.substr(last_uncovered, comparison_size) != data().substr(post_loop_offset, comparison_size)) {
            return false;
        }
        post_loop_offset += position_diff;
    }
    SILK_TRACE << "Iterator::has_prefix word_offset_=" << word_offset_ << "; post_loop_offset=" << post_loop_offset;
    return true;
}

uint64_t Decompressor::Iterator::next_compressed(Bytes& buffer) {
    const auto start_offset = word_offset_;

    uint64_t word_length = next_position(true);
    if (word_length == 0) {
        throw std::runtime_error{"invalid zero word length in: " + decoder_->compressed_filename()};
    }
    --word_length;  // because when we create HT we do ++ (0 is terminator)
    SILK_TRACE << "Iterator::next start_offset=" << start_offset << " word_length=" << word_length;
    if (word_length == 0) {
        if (bit_position_ > 0) {
            ++word_offset_;
            bit_position_ = 0;
        }
        return word_offset_;
    }

    // Track position into buffer where to insert part of the word
    size_t buffer_offset = buffer.size();
    buffer.resize(buffer_offset + word_length);
    SILK_TRACE << "Iterator::next buffer resized to: " << buffer.size();

    // Fill in the patterns
    size_t buffer_position = buffer_offset;
    for (auto pos{next_position(false)}; pos != 0; pos = next_position(false)) {
        // Positions where to insert patterns are encoded relative to one another
        buffer_position += pos - 1;
        const ByteView pattern = next_pattern();
        SILK_TRACE << "Iterator::next data-from-patterns pos=" << pos << " pattern=" << to_hex(pattern);
        if (buffer_position > buffer.size()) {
            return word_offset_;
        }
        pattern.copy(buffer.data() + buffer_position, std::min(pattern.size(), buffer.size() - buffer_position));
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
    buffer_position = buffer_offset;
    size_t last_uncovered = buffer_offset;

    // Fill in data which is not the patterns
    for (auto pos{next_position(false)}; pos != 0; pos = next_position(false)) {
        // Positions where to insert patterns are encoded relative to one another
        buffer_position += pos - 1;
        if (buffer_position > last_uncovered) {
            size_t position_diff = buffer_position - last_uncovered;
            SILK_TRACE << "Iterator::next other-data pos=" << pos << " last_uncovered=" << last_uncovered
                       << " buffer_position=" << buffer_position << " position_diff=" << position_diff
                       << " data=" << to_hex(ByteView{data().data() + post_loop_offset, position_diff});
            data().copy(buffer.data() + last_uncovered, std::min(position_diff, buffer.size() - last_uncovered), post_loop_offset);
            post_loop_offset += position_diff;
        }
        last_uncovered = buffer_position + next_pattern().size();
    }
    if (buffer_offset + word_length > last_uncovered) {
        size_t position_diff = buffer_offset + word_length - last_uncovered;
        SILK_TRACE << "Iterator::next other-data last_uncovered=" << last_uncovered
                   << " buffer_position=" << buffer_position << " position_diff=" << position_diff
                   << " data=" << to_hex(ByteView{data().data() + post_loop_offset, position_diff});
        data().copy(buffer.data() + last_uncovered, std::min(position_diff, buffer.size() - last_uncovered), post_loop_offset);
        post_loop_offset += position_diff;
    }
    word_offset_ = post_loop_offset;
    bit_position_ = 0;
    SILK_TRACE << "Iterator::next word_offset_=" << word_offset_;
    return post_loop_offset;
}

uint64_t Decompressor::Iterator::next_uncompressed(Bytes& buffer) {
    uint64_t word_length = next_position(true);
    if (word_length == 0) {
        throw std::runtime_error{"invalid zero word length in: " + decoder_->compressed_filename()};
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
    buffer.append(data().substr(word_position, word_length));
    return word_offset_;
}

uint64_t Decompressor::Iterator::skip_compressed() {
    uint64_t word_length = next_position(true);
    if (word_length == 0) {
        throw std::runtime_error{"invalid zero word length in: " + decoder_->compressed_filename()};
    }
    --word_length;  // because when we create HT we do ++ (0 is terminator)
    if (word_length == 0) {
        if (bit_position_ > 0) {
            ++word_offset_;
            bit_position_ = 0;
        }
        return word_offset_;
    }

    size_t uncovered_count{0};
    size_t buffer_position{0};
    size_t last_uncovered{0};
    for (auto pos{next_position(false)}; pos != 0; pos = next_position(false)) {
        // Positions where to insert are encoded relative to one another
        buffer_position += pos - 1;
        if (word_length < buffer_position) {
            throw std::logic_error{"likely index file is invalid: " + decoder_->compressed_filename()};
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
        throw std::runtime_error{"invalid zero word length in: " + decoder_->compressed_filename()};
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
    is_next_value_ = false;
    word_offset_ = data_offset;
    bit_position_ = 0;
}

ByteView Decompressor::Iterator::next_pattern() {
    const PatternTable* table = decoder_->pattern_dict_.get();
    if (table->bit_length() == 0) {
        const auto* codeword{table->codeword(0)};
        if (codeword == nullptr) {
            throw std::runtime_error{
                "Unexpected missing codeword for code: 0 in snapshot: " + decoder_->compressed_path().string()};
        }
        return codeword->pattern();
    }
    uint8_t length{0};
    ByteView pattern{};
    while (length == 0) {
        const uint16_t code = next_code(table->bit_length());

        const auto* codeword{table->search_condensed(code)};
        if (codeword == nullptr) {
            throw std::runtime_error{
                "Unexpected missing codeword for code: " + std::to_string(code) + " in snapshot: " + decoder_->compressed_path().string()};
        }
        length = codeword->code_length();
        if (length == 0) {
            table = codeword->table();
            bit_position_ += 9;  // CHAR_BIT + 1
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
        ++word_offset_;
        bit_position_ = 0;
    }
    SILK_TRACE << "Iterator::next_position word_offset_=" << word_offset_ << " bit_position_=" << int{bit_position_};
    const PositionTable* table = decoder_->position_dict_.get();
    if (table->bit_length() == 0) {
        SILK_TRACE << "Iterator::next_position table->position(0)=" << table->position(0);
        return table->position(0);
    }
    uint8_t length{0};
    uint64_t position{0};
    while (length == 0) {
        const uint16_t code = next_code(table->bit_length());
        length = table->length(code);
        if (length == 0) {
            table = table->child(code);
            bit_position_ += 9;  // CHAR_BIT + 1
        } else {
            bit_position_ += length;
            SILK_TRACE << "Iterator::next_position table->position(code)=" << table->position(code);
            position = table->position(code);
        }
        word_offset_ += bit_position_ / CHAR_BIT;
        bit_position_ = bit_position_ % CHAR_BIT;
    }
    return position;
}

uint16_t Decompressor::Iterator::next_code(size_t bit_length) {
    uint16_t code = static_cast<uint16_t>(decoder_->words_start_[word_offset_]) >> bit_position_;
    if (static_cast<size_t>(CHAR_BIT - bit_position_) < bit_length && word_offset_ + 1 < data_size()) {
        code |= decoder_->words_start_[word_offset_ + 1] << (CHAR_BIT - bit_position_);
    }
    code &= (1 << bit_length) - 1;
    return code;
}

bool Decompressor::Iterator::is_next_word_compressed() const {
    CompressionKind next_word_compression_kind = is_next_value_ ? CompressionKind::kValues : CompressionKind::kKeys;
    return (decoder_->compression_kind_ & next_word_compression_kind) != CompressionKind::kNone;
}

Decompressor::Iterator& Decompressor::Iterator::operator++() {
    if (has_next()) {
        current_word_offset_ = word_offset_;
        current_word_.clear();

        bool is_next_word_compressed = this->is_next_word_compressed();
        is_next_value_ = !is_next_value_;
        if (is_next_word_compressed) {
            next_compressed(current_word_);
        } else {
            next_uncompressed(current_word_);
        }
    } else {
        *this = make_end();
    }
    return *this;
}

uint64_t Decompressor::Iterator::skip() {
    bool is_next_word_compressed = this->is_next_word_compressed();
    is_next_value_ = !is_next_value_;
    return is_next_word_compressed ? skip_compressed() : skip_uncompressed();
}

bool operator==(const Decompressor::Iterator& lhs, const Decompressor::Iterator& rhs) {
    if (lhs.decoder_ == nullptr) {
        return (rhs.decoder_ == nullptr);
    }
    return (lhs.decoder_ == rhs.decoder_) &&
           (lhs.current_word_offset_ == rhs.current_word_offset_) &&
           (lhs.word_offset_ == rhs.word_offset_) &&
           (lhs.bit_position_ == rhs.bit_position_);
}

Decompressor::Iterator Decompressor::Iterator::make_end() {
    Iterator it{nullptr, {}};
    it.current_word_offset_ = std::numeric_limits<uint64_t>::max();
    it.word_offset_ = std::numeric_limits<uint64_t>::max();
    it.bit_position_ = std::numeric_limits<uint8_t>::max();
    return it;
}

}  // namespace silkworm::snapshots::seg
