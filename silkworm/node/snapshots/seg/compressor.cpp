/*
   Copyright 2024 The Silkworm Authors

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

#include "compressor.hpp"

#include <cassert>
#include <filesystem>
#include <fstream>
#include <numeric>
#include <vector>

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
constexpr size_t kSuperstringSamplingFactor = 4;

constexpr size_t kOutputStreamBufferSize = 1_Mebi;
constexpr size_t kIntermediateStreamBufferSize = kOutputStreamBufferSize * 4;

class CompressorImpl {
  public:
    CompressorImpl(
        const std::filesystem::path& path,
        const std::filesystem::path& tmp_dir_path)
        : path_(path),
          raw_words_file_path_(make_raw_words_file_path(path, tmp_dir_path)),
          raw_words_(raw_words_file_path_, kOutputStreamBufferSize),
          pattern_aggregator_(tmp_dir_path) {}
    ~CompressorImpl();

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

    std::filesystem::path path_;
    std::filesystem::path raw_words_file_path_;

    Superstring current_superstring_;
    size_t superstring_sample_cycle_index_{};

    RawWordsStream raw_words_;
    PatternExtractor pattern_extractor_;
    PatternAggregator pattern_aggregator_;
};

CompressorImpl::~CompressorImpl() {
    std::filesystem::remove(raw_words_file_path_);
    std::filesystem::remove(intermediate_file_path());
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

static std::vector<uint64_t> vector_reorder(const std::vector<uint64_t>& items, const std::vector<size_t>& order) {
    std::vector<uint64_t> result(items.size(), 0);
    for (size_t i = 0; i < result.size(); i++)
        result[i] = items[order[i]];
    return result;
}

static std::vector<size_t> invert_order(const std::vector<size_t>& order) {
    std::vector<size_t> result(order.size(), 0);
    for (size_t i = 0; i < result.size(); i++)
        result[order[i]] = i;
    return result;
}

void CompressorImpl::compress() {
    using Pattern = PatternAggregator::Pattern;

    raw_words_.flush();
    consume_superstring(current_superstring_);

    auto patterns = PatternAggregator::aggregate(std::move(pattern_aggregator_));

    PatriciaTree patterns_patricia_tree;
    for (auto& pattern : patterns) {
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
    std::vector<uint64_t> intermediate_pattern_codes(patterns.size());
    std::iota(intermediate_pattern_codes.begin(), intermediate_pattern_codes.end(), 0);

    size_t words_count = 0;
    size_t empty_words_count = 0;
    std::vector<uint64_t> pattern_uses(patterns.size(), 0);
    PositionsMap positions_map;

    raw_words_.rewind();
    while (auto entry = raw_words_.read_word()) {
        auto& [word, is_compressed] = entry.value();

        words_count++;
        if (word.empty()) empty_words_count++;

        compressed_word.raw_length = word.size();
        compressed_word.pattern_positions.clear();

        if (is_compressed) {
            auto& result = pattern_covering_search.cover_word(word);

            for (auto [pattern_pos, pattern_ptr] : result.pattern_positions) {
                auto pattern = reinterpret_cast<Pattern*>(pattern_ptr);
                auto pattern_index = static_cast<size_t>(std::distance(&patterns[0], pattern));

                pattern_uses[pattern_index]++;

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

    // pattern_uses_order maps patterns_code_table indexes to patterns indexes
    auto pattern_uses_order = huffman_code_table_order_by_uses_and_code(pattern_uses, intermediate_pattern_codes);
    // pattern2code_index maps patterns indexes to patterns_code_table indexes
    auto pattern2code_index = invert_order(pattern_uses_order);
    // sort pattern_uses by uses and intermediate codes
    auto pattern_uses_sorted = vector_reorder(pattern_uses, pattern_uses_order);

    auto patterns_code_table = huffman_code_table(pattern_uses_sorted);
    auto patterns_code_table_order = huffman_code_table_order_by_uses_and_code(pattern_uses_sorted, patterns_code_table);

    // calculate position uses
    auto positions = positions_map.list_positions();
    auto position_uses = positions_map.list_uses();

    // an intermediate position code is equal to the position value
    auto& intermediate_position_codes = positions;
    // position_uses_order maps positions_code_table indexes to positions indexes
    auto position_uses_order = huffman_code_table_order_by_uses_and_code(position_uses, intermediate_position_codes);
    // sort position_uses by uses and intermediate codes
    auto position_uses_sorted = vector_reorder(position_uses, position_uses_order);

    auto positions_code_table = huffman_code_table(position_uses_sorted);
    auto positions_code_table_order = huffman_code_table_order_by_uses_and_code(position_uses_sorted, positions_code_table);

    SegStream::Header seg_header{
        .words_count = words_count,
        .empty_words_count = empty_words_count,
    };

    for (size_t i : patterns_code_table_order) {
        size_t pattern_index = pattern_uses_order[i];
        auto& pattern = patterns[pattern_index];
        seg_header.patterns.push_back(SegStream::HuffmanCodeTableSymbol<ByteView>{
            patterns_code_table[i].code_bits,
            pattern.data,
        });
    }

    // pos2code maps position values to positions_code_table indexes
    std::map<size_t, size_t> pos2code_index;
    auto pos2code = [&](size_t position) -> const HuffmanSymbolCode& {
        return positions_code_table[pos2code_index[position]];
    };

    for (size_t i : positions_code_table_order) {
        size_t position_index = position_uses_order[i];
        auto position = static_cast<size_t>(positions[position_index]);
        seg_header.positions.push_back(SegStream::HuffmanCodeTableSymbol<size_t>{
            positions_code_table[i].code_bits,
            position,
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
        for (auto [pattern_position, pattern_index] : compressed_word1->pattern_positions) {
            auto position = PositionsMap::position(pattern_position, prev_pattern_position);
            auto& position_code = pos2code(position);
            prev_pattern_position = pattern_position;

            size_t pattern_code_index = pattern2code_index[pattern_index];
            auto& pattern_code = patterns_code_table[pattern_code_index];

            auto& pattern = patterns[pattern_index];
            uncovered_data_size -= pattern.data.size();

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
    const std::filesystem::path& tmp_dir_path)
    : p_impl_(std::make_unique<CompressorImpl>(path, tmp_dir_path)) {}
Compressor::~Compressor() { static_assert(true); }

Compressor::Compressor(Compressor&& other) noexcept
    : p_impl_(std::move(other.p_impl_)) {}
Compressor& Compressor::operator=(Compressor&& other) noexcept {
    p_impl_ = std::move(other.p_impl_);
    return *this;
}

void Compressor::add_word(ByteView word, bool is_compressed) {
    p_impl_->add_word(word, is_compressed);
}

void Compressor::compress(Compressor compressor) {
    compressor.p_impl_->compress();
}

}  // namespace silkworm::snapshots::seg
