// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "compressor.hpp"

#include <filesystem>
#include <fstream>
#include <limits>
#include <numeric>
#include <vector>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/base.hpp>

#include "compressor/bit_stream.hpp"
#include "compressor/huffman_code.hpp"
#include "compressor/intermediate_compressed_stream.hpp"
#include "compressor/output_file_transaction.hpp"
#include "compressor/patricia_tree.hpp"
#include "compressor/pattern_aggregator.hpp"
#include "compressor/pattern_covering.hpp"
#include "compressor/pattern_extractor.hpp"
#include "compressor/positions_map.hpp"
#include "compressor/raw_words_stream.hpp"
#include "compressor/seg_stream.hpp"

namespace silkworm::snapshots::seg {

/**
 * Pick every kWordSamplingFactor-th word for superstring inclusion.
 * Also drop superstrings unless their overflowing word is kWordSamplingFactor-th.
 */
static constexpr size_t kSuperstringSamplingFactor = 4;

static constexpr size_t kOutputStreamBufferSize = 1_Mebi;
static constexpr size_t kIntermediateStreamBufferSize = kOutputStreamBufferSize * 4;

class CompressorImpl {
  public:
    CompressorImpl(
        const std::filesystem::path& path,
        const std::filesystem::path& tmp_dir_path,
        CompressionKind compression_kind)
        : path_(path),
          compression_kind_(compression_kind),
          raw_words_file_path_(make_raw_words_file_path(path, tmp_dir_path)),
          raw_words_(raw_words_file_path_, RawWordsStream::OpenMode::kCreate, kOutputStreamBufferSize),
          pattern_aggregator_(tmp_dir_path) {}
    ~CompressorImpl();

    void add_word(ByteView word);
    void add_word(ByteView word, bool is_compressed);
    void compress();

  private:
    void consume_superstring(const Superstring& superstring);

    static std::filesystem::path make_raw_words_file_path(
        const std::filesystem::path& path,
        const std::filesystem::path& tmp_dir_path) {
        return tmp_dir_path / (path.filename().string() + ".idt");
    }

    std::filesystem::path intermediate_file_path() const {
        return path_.string() + ".tmp.tmp";
    }

    bool is_next_word_compressed() const;

    std::filesystem::path path_;

    CompressionKind compression_kind_;
    //! Flag indicating if next word is key (false) or value (true)
    bool is_next_value_{false};

    std::filesystem::path raw_words_file_path_;
    RawWordsStream raw_words_;

    Superstring current_superstring_;
    size_t superstring_sample_cycle_index_{};

    PatternExtractor pattern_extractor_;
    PatternAggregator pattern_aggregator_;
};

CompressorImpl::~CompressorImpl() {
    std::filesystem::remove(raw_words_file_path_);
    std::filesystem::remove(intermediate_file_path());
}

bool CompressorImpl::is_next_word_compressed() const {
    CompressionKind next_word_compression_kind = is_next_value_ ? CompressionKind::kValues : CompressionKind::kKeys;
    return (compression_kind_ & next_word_compression_kind) != CompressionKind::kNone;
}

void CompressorImpl::add_word(ByteView word) {
    add_word(word, is_next_word_compressed());
    is_next_value_ = !is_next_value_;
}

void CompressorImpl::add_word(ByteView word, bool is_compressed) {
    if (is_compressed) {
        if (!current_superstring_.can_add_word(word)) {
            if (superstring_sample_cycle_index_ == 0) {
                consume_superstring(current_superstring_);
            }
            current_superstring_.clear();
            superstring_sample_cycle_index_ = (superstring_sample_cycle_index_ + 1) % kSuperstringSamplingFactor;
        }

        current_superstring_.add_word(word, /* skip_copy = */ superstring_sample_cycle_index_);
    }

    raw_words_.write_word(word, is_compressed);
}

void CompressorImpl::consume_superstring(const Superstring& superstring) {
    pattern_extractor_.extract_patterns(superstring, [this](ByteView pattern, uint64_t score) {
        pattern_aggregator_.collect_pattern({Bytes{pattern}, score});
    });
}

template <typename T>
static std::vector<T> vector_reorder(const std::vector<T>& items, const std::vector<size_t>& order) {
    std::vector<T> result(items.size());
    for (size_t i = 0; i < result.size(); ++i)
        result[i] = items[order[i]];
    return result;
}

static std::vector<size_t> invert_order(const std::vector<size_t>& order) {
    std::vector<size_t> result(order.size(), 0);
    for (size_t i = 0; i < result.size(); ++i)
        result[order[i]] = i;
    return result;
}

void CompressorImpl::compress() {
    using Pattern = PatternAggregator::Pattern;

    raw_words_.flush();
    consume_superstring(current_superstring_);

    auto candidate_patterns = PatternAggregator::aggregate(std::move(pattern_aggregator_));

    PatriciaTree patterns_patricia_tree;
    for (auto& pattern : candidate_patterns) {
        patterns_patricia_tree.insert(pattern.data, &pattern);
    }

    PatternCoveringSearch pattern_covering_search{
        patterns_patricia_tree,
        [](void* pattern) { return reinterpret_cast<Pattern*>(pattern)->score; },
    };

    IntermediateCompressedStream intermediate_stream{
        intermediate_file_path(),
        kIntermediateStreamBufferSize,
    };

    IntermediateCompressedStream::CompressedWord compressed_word{};
    Bytes word_uncovered_data;

    // a pattern code for the intermediate file is equal to the index
    std::vector<uint64_t> intermediate_pattern_codes(candidate_patterns.size());
    std::iota(intermediate_pattern_codes.begin(), intermediate_pattern_codes.end(), 0);

    size_t words_count = 0;
    size_t empty_words_count = 0;
    std::vector<uint64_t> pattern_uses(candidate_patterns.size(), 0);
    PositionsMap positions_map;

    raw_words_.rewind();
    while (auto entry = raw_words_.read_word()) {
        auto& [word, is_compressed] = entry.value();

        ++words_count;
        if (word.empty()) ++empty_words_count;

        compressed_word.raw_length = word.size();
        compressed_word.pattern_positions.clear();

        if (is_compressed) {
            auto& result = pattern_covering_search.cover_word(word);

            for (auto [pattern_pos, pattern_ptr] : result.pattern_positions) {
                auto pattern = reinterpret_cast<Pattern*>(pattern_ptr);
                auto pattern_index = static_cast<size_t>(std::distance(&candidate_patterns[0], pattern));

                ++pattern_uses[pattern_index];

                size_t pattern_code = intermediate_pattern_codes[pattern_index];
                compressed_word.pattern_positions.emplace_back(pattern_pos, pattern_code);
            }

            word_uncovered_data.clear();
            for (auto [start, end] : result.uncovered_ranges) {
                word_uncovered_data.append(
                    word.cbegin() + static_cast<Bytes::difference_type>(start),
                    word.cbegin() + static_cast<Bytes::difference_type>(end));
            }

            intermediate_stream.write_word(compressed_word);
            intermediate_stream.write_uncovered_data(word_uncovered_data);
        } else {
            intermediate_stream.write_word(compressed_word);
            intermediate_stream.write_uncovered_data(word);
        }

        positions_map.update_with_word(compressed_word.raw_length, compressed_word.pattern_positions);
    }
    intermediate_stream.flush();

    // once we ran pattern_covering_search on all the words, we know which candidate patterns are actually used
    // let's remove the unused candidate patterns from consideration
    std::vector<Bytes> patterns;
    size_t used_patterns_count = 0;
    // candidate2pattern_index maps candidate patterns indexes to the used patterns indexes
    std::vector<size_t> candidate2pattern_index(candidate_patterns.size(), std::numeric_limits<size_t>::max());
    for (size_t i = 0; i < candidate_patterns.size(); ++i) {
        if (pattern_uses[i] == 0) continue;
        patterns.emplace_back(std::move(candidate_patterns[i].data));
        intermediate_pattern_codes[used_patterns_count] = intermediate_pattern_codes[i];
        pattern_uses[used_patterns_count] = pattern_uses[i];
        candidate2pattern_index[i] = used_patterns_count;
        ++used_patterns_count;
    }
    intermediate_pattern_codes.resize(used_patterns_count);
    pattern_uses.resize(used_patterns_count);

    {
        // sort patterns and pattern_uses by uses and intermediate codes
        auto pattern_uses_order = huffman_code_table_order_by_uses_and_codes(pattern_uses, intermediate_pattern_codes);
        patterns = vector_reorder(patterns, pattern_uses_order);
        pattern_uses = vector_reorder(pattern_uses, pattern_uses_order);

        // pattern2code_index maps old pattern indexes to patterns_code_table indexes
        auto pattern2code_index = invert_order(pattern_uses_order);
        for (size_t& index : candidate2pattern_index) {
            if (index < std::numeric_limits<size_t>::max()) {
                index = pattern2code_index[index];
            }
        }
    }

    auto patterns_code_table = huffman_code_table(pattern_uses);
    auto patterns_code_table_order = huffman_code_table_order_by_codes(patterns_code_table);

    // calculate position uses
    auto positions = positions_map.list_positions();
    auto position_uses = positions_map.list_uses();

    {
        // sort positions and position_uses by uses and intermediate codes
        // an intermediate position code is equal to the position value
        auto& intermediate_position_codes = positions;
        auto position_uses_order = huffman_code_table_order_by_uses_and_codes(position_uses, intermediate_position_codes);
        positions = vector_reorder(positions, position_uses_order);
        position_uses = vector_reorder(position_uses, position_uses_order);
    }

    auto positions_code_table = huffman_code_table(position_uses);
    auto positions_code_table_order = huffman_code_table_order_by_codes(positions_code_table);

    SegStream::Header seg_header{
        .words_count = words_count,
        .empty_words_count = empty_words_count,
    };

    for (size_t i : patterns_code_table_order) {
        uint8_t code_bits = patterns_code_table[i].code_bits;
        auto& pattern = patterns[i];
        seg_header.patterns.push_back(SegStream::HuffmanCodeTableSymbol<ByteView>{
            .code_bits = code_bits,
            .data = pattern,
        });
    }

    // pos2code maps position values to positions_code_table indexes
    std::map<size_t, size_t> pos2code_index;
    auto pos2code = [&](size_t position) -> const HuffmanSymbolCode& {
        return positions_code_table[pos2code_index[position]];
    };

    for (size_t i : positions_code_table_order) {
        uint8_t code_bits = positions_code_table[i].code_bits;
        auto position = static_cast<size_t>(positions[i]);
        seg_header.positions.push_back(SegStream::HuffmanCodeTableSymbol<size_t>{
            .code_bits = code_bits,
            .data = position,
        });
        pos2code_index[position] = i;
    }

    OutputFileTransaction out_file{path_, kOutputStreamBufferSize};
    SegStream seg_stream{out_file.stream()};
    seg_stream.write_header(seg_header);

    auto write_code = [&seg_stream](const HuffmanSymbolCode& code) {
        seg_stream.codes().write(code.code, code.code_bits);
    };

    intermediate_stream.rewind();
    while (auto compressed_word1 = intermediate_stream.read_word()) {
        size_t raw_length = compressed_word1->raw_length;
        auto& raw_length_code = pos2code(PositionsMap::word_length_position(raw_length));
        write_code(raw_length_code);
        if (raw_length == 0) {
            seg_stream.codes().flush();
            continue;
        }

        size_t uncovered_data_size = raw_length;
        size_t prev_pattern_position = 0;
        size_t prev_pattern_end = 0;
        for (auto [pattern_position, candidate_pattern_index] : compressed_word1->pattern_positions) {
            auto position = PositionsMap::position(pattern_position, prev_pattern_position);
            auto& position_code = pos2code(position);
            prev_pattern_position = pattern_position;

            size_t pattern_index = candidate2pattern_index[candidate_pattern_index];
            auto& pattern_code = patterns_code_table[pattern_index];

            auto& pattern = patterns[pattern_index];
            size_t pattern_end = pattern_position + pattern.size();
            // the patterns might overlap (pattern_position < prev_pattern_end),
            // in this case covered_size is less than the pattern size
            size_t covered_size = pattern_end - std::max(pattern_position, prev_pattern_end);
            uncovered_data_size -= covered_size;
            prev_pattern_end = pattern_end;

            write_code(position_code);
            write_code(pattern_code);
        }

        auto& terminator_position_code = pos2code(PositionsMap::kTerminatorPosition);
        write_code(terminator_position_code);
        seg_stream.codes().flush();

        Bytes uncovered_data = intermediate_stream.read_uncovered_data(uncovered_data_size);
        seg_stream.write_uncovered_data(uncovered_data);
    }

    out_file.commit();
}

Compressor::Compressor(
    const std::filesystem::path& path,
    const std::filesystem::path& tmp_dir_path,
    CompressionKind compression_kind)
    : p_impl_{std::make_unique<CompressorImpl>(path, tmp_dir_path, compression_kind)} {}
Compressor::~Compressor() { static_assert(true); }

Compressor::Compressor(Compressor&& other) noexcept
    : p_impl_(std::move(other.p_impl_)) {}
Compressor& Compressor::operator=(Compressor&& other) noexcept {
    p_impl_ = std::move(other.p_impl_);
    return *this;
}

void Compressor::add_word(ByteView word) {
    p_impl_->add_word(word);
}

void Compressor::add_word(ByteView word, bool is_compressed) {
    p_impl_->add_word(word, is_compressed);
}

void Compressor::compress(Compressor compressor) {
    compressor.p_impl_->compress();
}

}  // namespace silkworm::snapshots::seg
