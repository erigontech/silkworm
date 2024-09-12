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

#pragma once

#include <array>
#include <filesystem>
#include <iterator>
#include <memory>
#include <ostream>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/infra/common/memory_mapped_file.hpp>

namespace silkworm::snapshots::seg {

class DecodingTable {
  public:
    //! The max bit length for tables (we don't use tables larger than 2^9)
    constexpr static std::size_t kMaxTableBitLength{9};

    [[nodiscard]] std::size_t bit_length() const { return bit_length_; }

  protected:
    explicit DecodingTable(std::size_t max_depth);

    std::size_t bit_length_{0};
    std::size_t max_depth_;
};

class PatternTable;

class CodeWord {
  public:
    explicit CodeWord();
    explicit CodeWord(uint16_t code, uint8_t length, ByteView pattern);
    explicit CodeWord(uint16_t code, uint8_t length, ByteView pattern, std::unique_ptr<PatternTable> table, CodeWord* next);

    [[nodiscard]] uint16_t code() const { return code_; }
    [[nodiscard]] uint8_t code_length() const { return code_length_; }
    [[nodiscard]] ByteView pattern() const { return pattern_; }
    [[nodiscard]] PatternTable* table() const { return table_.get(); }
    [[nodiscard]] CodeWord* next() const { return next_; }

    void reset_content(uint16_t code, uint8_t length, ByteView pattern);

    void set_next(CodeWord* next);

  private:
    //! Code associated to the symbol
    uint16_t code_{0};
    //! Number of bits in the codes
    uint8_t code_length_{0};
    ByteView pattern_;
    std::unique_ptr<PatternTable> table_;
    CodeWord* next_;
};

struct Pattern {
    uint64_t depth{};
    ByteView value;
};

class PatternTable : public DecodingTable {
  public:
    //! The default bit length threshold after which tables are condensed (default: all NOT condensed)
    constexpr static std::size_t kDefaultCondensedTableBitLengthThreshold = kMaxTableBitLength;
    constexpr static int kNumPowers{10};
    constexpr static int kMaxPower{512};
    using WordDistances = std::array<std::vector<int>, kNumPowers>;

    //! @brief Set the bit length threshold after which tables will be condensed.
    //! @attention Condensing reduces size of decompression table but leads to slower reads.
    //! @details Tables with bit length greater than threshold will be condensed. To disable condensing completely
    //! set `condensed_table_bit_length_threshold` to 9; to enable condensing for all tables, set it to 0; to
    //! enable condensing for tables of size greater than 64, set it to 6.
    static void set_condensed_table_bit_length_threshold(std::size_t condensed_table_bit_length_threshold);

    explicit PatternTable(std::size_t max_depth);

    [[nodiscard]] const CodeWord* codeword(std::size_t code) const {
        return code < codewords_.size() ? codewords_[code] : nullptr;
    }

    [[nodiscard]] std::size_t num_codewords() const { return codewords_.size(); }

    [[nodiscard]] const CodeWord* search_condensed(uint16_t code) const;

    std::size_t build_condensed(std::span<Pattern> patterns);

  private:
    static const WordDistances kWordDistances;
    static std::size_t condensed_table_bit_length_threshold_;

    [[nodiscard]] static bool check_distance(std::size_t power, int distance);

    std::size_t build_condensed(
        std::span<Pattern> patterns,
        uint64_t highest_depth,
        uint16_t code,
        int bits,
        uint64_t depth);

    [[maybe_unused]] CodeWord* insert_word(CodeWord* codeword);

    std::vector<CodeWord*> codewords_;
    std::vector<std::unique_ptr<CodeWord>> codewords_list_;
    mutable CodeWord* head_{nullptr};

    friend std::ostream& operator<<(std::ostream& out, const PatternTable& pt);
};

struct Position {
    uint64_t depth;
    uint64_t value;
};

class PositionTable : public DecodingTable {
  public:
    explicit PositionTable(std::size_t max_depth);

    [[nodiscard]] std::size_t num_positions() const { return positions_.size(); }

    [[nodiscard]] uint64_t position(std::size_t code) const {
        return code < positions_.size() ? positions_[code] : 0;
    }

    [[nodiscard]] uint8_t length(std::size_t code) const {
        return code < lengths_.size() ? lengths_[code] : 0;
    }

    [[nodiscard]] PositionTable* child(std::size_t code) const {
        return code < children_.size() ? children_[code].get() : nullptr;
    }

    int build(std::span<Position> positions);

  private:
    int build_tree(
        std::span<Position> positions,
        uint64_t highest_depth,
        uint16_t code,
        int bits,
        uint64_t depth);

    std::vector<uint64_t> positions_;
    std::vector<uint8_t> lengths_;
    std::vector<std::unique_ptr<PositionTable>> children_;

    friend std::ostream& operator<<(std::ostream& out, const PositionTable& pt);
};

//! Snapshot decoder using modified Condensed Huffman Table (CHT) algorithm
class Decompressor {
  public:
    //! The max number of patterns in decoding tables
    constexpr static std::size_t kMaxTablePatterns = (1 << DecodingTable::kMaxTableBitLength) * 510;

    //! The max number of positions in decoding tables
    constexpr static std::size_t kMaxTablePositions = (1 << DecodingTable::kMaxTableBitLength) * 100;

    enum class ReadMode : uint8_t {
        kNormal,
        kRandom,
        kSequential,
    };

    class ReadModeGuard;

    //! Read-only access to the file data stream
    class Iterator {
      public:
        Iterator(const Decompressor* decoder, std::shared_ptr<ReadModeGuard> read_mode_guard);

        [[nodiscard]] std::size_t data_size() const { return decoder_->words_length_; }

        //! Check if any next word is present in the data stream
        [[nodiscard]] bool has_next() const { return word_offset_ < decoder_->words_length_; }

        //! Check if the word at the current offset has the specified prefix (this does not move offset to the next)
        [[nodiscard]] bool has_prefix(ByteView prefix);

        //! Extract one *compressed* word from current offset in the file and append it to buffer
        //! After extracting current word, move at the beginning of the next one
        //! @return the next word position
        uint64_t next(Bytes& buffer);

        //! Extract one *uncompressed* word from current offset in the file and append it to buffer
        //! After extracting current word, move at the beginning of the next one
        //! @return the next word position
        uint64_t next_uncompressed(Bytes& buffer);

        //! Move at the offset of the next *compressed* word skipping current one
        //! @return the next word position
        uint64_t skip();

        //! Move at the offset of the next *uncompressed* word skipping current one
        //! @return the next word position
        uint64_t skip_uncompressed();

        //! Reset to the specified offset in the data stream
        void reset(uint64_t data_offset);

        //! The current word position
        uint64_t current_word_offset() const { return current_word_offset_; }

        //! input_iterator concept boilerplate

        using iterator_category [[maybe_unused]] = std::input_iterator_tag;
        using difference_type = std::ptrdiff_t;
        using value_type = Bytes;
        using pointer = value_type*;
        using reference = value_type&;

        reference operator*() { return current_word_; }
        pointer operator->() { return &current_word_; }

        Iterator operator++(int) { return std::exchange(*this, ++Iterator{*this}); }
        Iterator& operator++();

        friend bool operator!=(const Iterator& lhs, const Iterator& rhs) = default;
        friend bool operator==(const Iterator& lhs, const Iterator& rhs);

        static Iterator make_end(const Decompressor* decoder);

      private:
        //! View on the whole data stream.
        [[nodiscard]] inline ByteView data() const;

        //! Read the next pattern from the data stream
        [[nodiscard]] ByteView next_pattern();

        //! Read the next position from the data stream
        [[nodiscard]] uint64_t next_position(bool clean);

        //! Read next code from the data stream
        [[nodiscard]] inline uint16_t next_code(std::size_t bit_length);

        //! The decoder on which iterator works
        const Decompressor* decoder_;

        //! Position of current word in the data file
        uint64_t current_word_offset_{0};

        //! Position of the next word
        uint64_t word_offset_{0};

        //! Bit position [0..7] in current word of the data file
        uint8_t bit_position_{0};

        //! Last extracted word
        Bytes current_word_;

        std::shared_ptr<ReadModeGuard> read_mode_guard_;
    };

    static_assert(std::input_or_output_iterator<Iterator>);

    explicit Decompressor(std::filesystem::path compressed_path, std::optional<MemoryMappedRegion> compressed_region = {});
    ~Decompressor();

    Decompressor(Decompressor&&) = default;
    Decompressor& operator=(Decompressor&&) = default;

    [[nodiscard]] const std::filesystem::path& compressed_path() const { return compressed_path_; }

    [[nodiscard]] std::string compressed_filename() const { return compressed_path_.filename().string(); }

    [[nodiscard]] uint64_t words_count() const { return words_count_; }

    [[nodiscard]] uint64_t empty_words_count() const { return empty_words_count_; }

    [[nodiscard]] std::filesystem::file_time_type last_write_time() const {
        return compressed_file_->last_write_time();
    }

    [[nodiscard]] bool is_open() const { return compressed_file_ != nullptr; }

    [[nodiscard]] const MemoryMappedFile* memory_file() const { return compressed_file_.get(); }

    void open();

    //! Get an iterator to the compressed data
    [[nodiscard]] Iterator make_iterator() const { return Iterator{this, {}}; }

    //! Begin reading the words, expected to read in sequential order
    Iterator begin() const;
    Iterator end() const { return Iterator::make_end(this); }

    /**
     * Returns an iterator at a given offset.
     * If the offset is invalid it returns end().
     * Seek makes sure that the result starts with a given prefix, otherwise returns end().
     */
    Iterator seek(uint64_t offset, ByteView prefix = {}) const;

    void close();

  private:
    void read_patterns(ByteView dict);

    void read_positions(ByteView dict);

    //! The path to the compressed file
    std::filesystem::path compressed_path_;
    std::optional<MemoryMappedRegion> compressed_region_;

    //! The memory-mapped compressed file
    std::unique_ptr<MemoryMappedFile> compressed_file_;

    //! The number of words in the data
    uint64_t words_count_{0};

    //! The number of *empty* words in the data
    uint64_t empty_words_count_{0};

    //! The table of patterns used to decode the data words
    std::unique_ptr<PatternTable> pattern_dict_;

    //! The table of positions used to decode the data words
    std::unique_ptr<PositionTable> position_dict_;

    //! The start offset of the data words
    uint8_t* words_start_{nullptr};

    //! The size in bytes of the data words
    uint64_t words_length_{0};
};

}  // namespace silkworm::snapshots::seg
