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

#include <algorithm>
#include <filesystem>
#include <map>
#include <span>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

#include <absl/strings/str_split.h>
#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_exception.hpp>

#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/test_util/null_stream.hpp>
#include <silkworm/db/datastore/snapshots/segment/seg/decompressor.hpp>
#include <silkworm/db/test_util/temp_snapshots.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::snapshots {

using Catch::Matchers::Message;
namespace test = test_util;
using silkworm::test_util::null_stream;
using silkworm::test_util::TemporaryFile;
using namespace snapshots::seg;

//! DecodingTable exposed for white-box testing
class DecodingTableForTest : public DecodingTable {
  public:
    explicit DecodingTableForTest(size_t max_depth) : DecodingTable(max_depth) {}
    size_t max_depth() const { return max_depth_; }
};

//! set_condensed_table_bit_length_threshold
class SetCondensedTableBitLengthThresholdGuard {
  public:
    explicit SetCondensedTableBitLengthThresholdGuard(size_t threshold) {
        PatternTable::set_condensed_table_bit_length_threshold(threshold);
    }
    ~SetCondensedTableBitLengthThresholdGuard() {
        PatternTable::set_condensed_table_bit_length_threshold(PatternTable::kDefaultCondensedTableBitLengthThreshold);
    }
};

TEST_CASE("DecodingTable::DecodingTable", "[silkworm][node][seg][decompressor]") {
    std::map<std::string, std::pair<size_t, size_t>> test_params{
        {"max depth is 0", {0, 0}},
        {"max depth is < kMaxTableBitLength", {DecodingTable::kMaxTableBitLength - 1, DecodingTable::kMaxTableBitLength - 1}},
        {"max depth is = kMaxTableBitLength", {DecodingTable::kMaxTableBitLength, DecodingTable::kMaxTableBitLength}},
        {"max depth is > kMaxTableBitLength", {DecodingTable::kMaxTableBitLength + 1, DecodingTable::kMaxTableBitLength}},
    };
    for (const auto& [test_name, test_pair] : test_params) {
        size_t max_depth = test_pair.first;
        size_t expected_bit_length = test_pair.second;
        DecodingTableForTest table{max_depth};
        CHECK(table.max_depth() == max_depth);
        CHECK(table.bit_length() == expected_bit_length);
    }
}

TEST_CASE("CodeWord::CodeWord", "[silkworm][node][seg][decompressor]") {
    std::vector<CodeWord> codewords{};
    codewords.emplace_back();
    codewords.emplace_back(0, 0, ByteView{});
    codewords.emplace_back(0, 0, ByteView{}, nullptr, nullptr);
    for (const auto& cw : codewords) {
        CHECK(cw.code() == 0);
        CHECK(cw.code_length() == 0);
        CHECK(cw.pattern().empty());
        CHECK(cw.table() == nullptr);
        CHECK(cw.next() == nullptr);
    }
}

TEST_CASE("CodeWord::reset_content", "[silkworm][node][seg][decompressor]") {
    CodeWord parent_cw{};

    uint16_t old_code{121};
    uint8_t old_length{2};
    Bytes old_pattern{0x11, 0x00, 0x11};
    auto table_ptr = std::make_unique<PatternTable>(3);
    const PatternTable* table = table_ptr.get();
    CodeWord cw{old_code, old_length, old_pattern, std::move(table_ptr), &parent_cw};
    CHECK(cw.code() == old_code);
    CHECK(cw.code_length() == old_length);
    CHECK(cw.pattern() == old_pattern);
    CHECK(cw.table() == table);
    CHECK(cw.next() == &parent_cw);

    uint16_t new_code{111};
    uint8_t new_length{1};
    Bytes new_pattern{0x00, 0x11, 0x00};
    CHECK_NOTHROW(cw.reset_content(new_code, new_length, new_pattern));

    CHECK(cw.code() == new_code);
    CHECK(cw.code_length() == new_length);
    CHECK(cw.pattern() == new_pattern);
    CHECK(cw.table() == nullptr);
    CHECK(cw.next() == &parent_cw);
}

TEST_CASE("CodeWord::set_next", "[silkworm][node][seg][decompressor]") {
    CodeWord parent1_cw{}, parent2_cw{};
    CodeWord cw{0, 0, Bytes{}, std::make_unique<PatternTable>(3), &parent1_cw};
    CHECK(cw.next() == &parent1_cw);

    CHECK_NOTHROW(cw.set_next(&parent2_cw));

    CHECK(cw.next() == &parent2_cw);
}

TEST_CASE("PatternTable::set_condensed_table_bit_length_threshold", "[silkworm][node][seg][decompressor]") {
    SECTION("condensed_table_bit_length_threshold < kMaxTableBitLength") {
        CHECK_NOTHROW(SetCondensedTableBitLengthThresholdGuard(PatternTable::kMaxTableBitLength - 1));
    }
    SECTION("condensed_table_bit_length_threshold = kMaxTableBitLength") {
        CHECK_NOTHROW(SetCondensedTableBitLengthThresholdGuard(PatternTable::kMaxTableBitLength));
    }
    SECTION("condensed_table_bit_length_threshold > kMaxTableBitLength") {
        CHECK_THROWS_AS(SetCondensedTableBitLengthThresholdGuard(PatternTable::kMaxTableBitLength + 1), std::invalid_argument);
    }
}

TEST_CASE("PatternTable::PatternTable", "[silkworm][node][seg][decompressor]") {
    PatternTable table{0};
    CHECK(table.num_codewords() == 1);
    CHECK(table.codeword(0) == nullptr);
    CHECK(table.codeword(table.num_codewords()) == nullptr);
}

TEST_CASE("PatternTable::build_condensed", "[silkworm][node][seg][decompressor]") {
    std::span<Pattern> patterns0{};
    Bytes v1{0x00, 0x11};
    std::vector<Pattern> patterns1{{0, v1}};
    Bytes v2{0x00, 0x22};
    std::vector<Pattern> patterns2{{1, v1}, {2, v2}};
    std::map<std::string, std::span<Pattern>> test_spans{
        {"zero patterns", patterns0},
        {"one pattern", std::span<Pattern>{patterns1.data(), patterns1.size()}},
        {"two patterns", std::span<Pattern>{patterns2.data(), patterns2.size()}},
    };

    PatternTable table{2};  // max_depth in all patterns
    for (const auto& [test_name, pattern_span] : test_spans) {
        SECTION(test_name) {
            CHECK(table.build_condensed(pattern_span) == pattern_span.size());
        }
    }
}

TEST_CASE("PatternTable::search_condensed", "[silkworm][node][seg][decompressor]") {
    PatternTable table1{0};
    CHECK(table1.search_condensed(0) == nullptr);
    PatternTable table2{DecodingTable::kMaxTableBitLength + 1};
    CHECK(table2.search_condensed(0) == nullptr);
}

TEST_CASE("PatternTable::operator<<", "[silkworm][node][seg][decompressor]") {
    PatternTable table1{0};
    CHECK_NOTHROW(null_stream() << table1);
    SetCondensedTableBitLengthThresholdGuard bit_length_threshold_guard{1};
    PatternTable table2{0};
    CHECK_NOTHROW(null_stream() << table2);
}

TEST_CASE("PositionTable::PositionTable", "[silkworm][node][seg][decompressor]") {
    PositionTable table{0};
    CHECK(table.num_positions() == 1);
    CHECK(table.position(0) == 0);
    CHECK(table.length(0) == 0);
    CHECK(table.child(0) == nullptr);
    CHECK(table.position(table.num_positions()) == 0);
    CHECK(table.length(table.num_positions()) == 0);
    CHECK(table.child(table.num_positions()) == nullptr);
}

TEST_CASE("PositionTable::operator<<", "[silkworm][node][seg][decompressor]") {
    PositionTable table{0};
    CHECK_NOTHROW(null_stream() << table);
}

static test::TemporarySnapshotFile create_snapshot_file(
    const TemporaryDirectory& tmp_dir,
    std::vector<test::SnapshotPattern> patterns,
    std::vector<test::SnapshotPosition> positions) {
    test::SnapshotHeader header{
        .words_count = 0,
        .empty_words_count = 0,
        .patterns = std::move(patterns),
        .positions = std::move(positions),
    };
    return test::TemporarySnapshotFile{tmp_dir.path(), test::SampleHeaderSnapshotFile::kHeadersSnapshotFileName, header};
}

static test::TemporarySnapshotFile create_empty_snapshot_file(const TemporaryDirectory& tmp_dir) {
    return create_snapshot_file(tmp_dir, {}, {});
}

TEST_CASE("Decompressor::Decompressor from memory", "[silkworm][node][seg][decompressor]") {
    TemporaryDirectory tmp_dir;
    test::TemporarySnapshotFile tmp_snapshot = create_empty_snapshot_file(tmp_dir);
    MemoryMappedFile mmf{tmp_snapshot.fs_path()};
    Decompressor decoder_from_memory{tmp_snapshot.fs_path(), mmf.region()};
    CHECK(decoder_from_memory.compressed_path() == tmp_snapshot.fs_path());
    CHECK(decoder_from_memory.words_count() == 0);
    CHECK(decoder_from_memory.empty_words_count() == 0);
}

TEST_CASE("Decompressor::open invalid files", "[silkworm][node][seg][decompressor]") {
    SECTION("empty file") {
        TemporaryFile tmp_file;
        CHECK_THROWS_AS((Decompressor{tmp_file.path()}), std::runtime_error);
    }
    SECTION("compressed file is too short: 1") {
        TemporaryFile tmp_file;
        tmp_file.write(*silkworm::from_hex("0"));
        CHECK_THROWS_MATCHES((Decompressor{tmp_file.path()}), std::runtime_error, Message("compressed file is too short: 1"));
    }
    SECTION("compressed file is too short: 31") {
        TemporaryFile tmp_file;
        tmp_file.write(*silkworm::from_hex("0x00000000000000000000000000000000000000000000000000000000000000"));
        CHECK_THROWS_MATCHES((Decompressor{tmp_file.path()}), std::runtime_error, Message("compressed file is too short: 31"));
    }
    SECTION("invalid pattern_dict_length for compressed file size: 32") {
        TemporaryFile tmp_file1;
        tmp_file1.write(*silkworm::from_hex("0x000000000000000C000000000000000400000000000000150309000000000000"));
        CHECK_THROWS_MATCHES((Decompressor{tmp_file1.path()}), std::runtime_error, Message("invalid pattern_dict_length for compressed file size: 32"));
        TemporaryFile tmp_file2;
        tmp_file2.write(*silkworm::from_hex("0x0000000000000000000000000000000000000000000000010000000000000000"));
        CHECK_THROWS_MATCHES((Decompressor{tmp_file2.path()}), std::runtime_error, Message("invalid pattern_dict_length for compressed file size: 32"));
    }
    SECTION("invalid pattern_dict_length for compressed file size: 34") {
        TemporaryFile tmp_file;
        tmp_file.write(*silkworm::from_hex("0x000000000000000C00000000000000040000000000000016000000000000000003ff"));
        CHECK_THROWS_MATCHES((Decompressor{tmp_file.path()}), std::runtime_error, Message("invalid pattern_dict_length for compressed file size: 34"));
    }
    SECTION("invalid position_dict_length for compressed file size: 34") {
        TemporaryFile tmp_file1;
        tmp_file1.write(*silkworm::from_hex("0x000000000000000C0000000000000004000000000000000000000000000000160309"));
        CHECK_THROWS_MATCHES((Decompressor{tmp_file1.path()}), std::runtime_error, Message("invalid position_dict_length for compressed file size: 34"));
        TemporaryFile tmp_file2;
        tmp_file2.write(*silkworm::from_hex("0x000000000000000C00000000000000040000000000000000000000000000001603ff"));
        CHECK_THROWS_MATCHES((Decompressor{tmp_file2.path()}), std::runtime_error, Message("invalid position_dict_length for compressed file size: 34"));
    }
}

TEST_CASE("Decompressor::open valid files", "[silkworm][node][seg][decompressor]") {
    TemporaryDirectory tmp_dir;

    std::map<std::string, test::SnapshotHeader> header_tests{
        {
            "zero patterns and zero positions",
            test::SnapshotHeader{},
        },
        {
            "one pattern and zero positions",
            test::SnapshotHeader{
                .words_count = 0,
                .empty_words_count = 0,
                .patterns = std::vector<test::SnapshotPattern>{{12, {0x11, 0x22}}},
                .positions = std::vector<test::SnapshotPosition>{},
            },
        },
        {
            "zero patterns and one position",
            test::SnapshotHeader{
                .words_count = 0,
                .empty_words_count = 0,
                .patterns = std::vector<test::SnapshotPattern>{},
                .positions = std::vector<test::SnapshotPosition>{{0, 22}},
            },
        },
        {
            "one pattern and one position",
            test::SnapshotHeader{
                .words_count = 0,
                .empty_words_count = 0,
                .patterns = std::vector<test::SnapshotPattern>{{12, {}}},
                .positions = std::vector<test::SnapshotPosition>{{13, 22}},
            },
        },
        {
            "two patterns and one position",
            test::SnapshotHeader{
                .words_count = 0,
                .empty_words_count = 0,
                .patterns = std::vector<test::SnapshotPattern>{{1, {}}, {2, {}}},
                .positions = std::vector<test::SnapshotPosition>{{0, 22}},
            },
        },
    };

    for (auto& [test_name, header] : header_tests) {
        SECTION(test_name) {
            test::TemporarySnapshotFile tmp_snapshot{tmp_dir.path(), test::SampleHeaderSnapshotFile::kHeadersSnapshotFileName, header};
            Decompressor decoder{tmp_snapshot.fs_path()};
        }
    }
}

TEST_CASE("Iterator::Iterator empty data", "[silkworm][node][seg][decompressor]") {
    TemporaryDirectory tmp_dir;
    test::TemporarySnapshotFile tmp_snapshot = create_empty_snapshot_file(tmp_dir);
    Decompressor decoder{tmp_snapshot.fs_path()};

    SECTION("init") {
        CHECK(decoder.compressed_path() == tmp_snapshot.fs_path());
        CHECK(decoder.words_count() == 0);
        CHECK(decoder.empty_words_count() == 0);
    }
    SECTION("data_size") {
        CHECK(decoder.make_iterator().data_size() == 0);
    }
    SECTION("has_next") {
        CHECK_FALSE(decoder.make_iterator().has_next());
    }
    SECTION("next") {
        Bytes buffer;
        CHECK_THROWS_AS(decoder.make_iterator().next_compressed(buffer), std::runtime_error);
    }
    SECTION("next_uncompressed") {
        ByteView buffer_view;
        CHECK_THROWS_AS(decoder.make_iterator().next_uncompressed(buffer_view), std::runtime_error);
    }
    SECTION("skip") {
        CHECK_THROWS_AS(decoder.make_iterator().skip_compressed(), std::runtime_error);
    }
    SECTION("skip_uncompressed") {
        CHECK_THROWS_AS(decoder.make_iterator().skip_uncompressed(), std::runtime_error);
    }
}

static const std::string kLoremIpsum{
    "Lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et\n"
    "dolore magna aliqua Ut enim ad minim veniam quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo\n"
    "consequat Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur\n"
    "Excepteur sint occaecat cupidatat non proident sunt in culpa qui officia deserunt mollit anim id est laborum"};

static const std::vector<std::string> kLoremIpsumWords = absl::StrSplit(kLoremIpsum, ' ');

static const Bytes kLoremIpsumDict{*from_hex(
    "000000000000004200000000000000000000000000000000000000000000001e"
    "010003060409040b040a050d07100716071107050507060c0715070e04080f4c"
    "6f72656d20300f697073756d20310f646f6c6f72203201736974203307616d65"
    "74203477636f6e736563746574757220350b61646970697363696e6720360765"
    "6c697420370173656420387b646f20390d656975736d6f642031300374656d70"
    "6f7220313177696e6369646964756e74203132017574203133036c61626f7265"
    "2031340b65740a646f6c6f7265203135056d61676e6120313603616c69717561"
    "2031370155742031380f656e696d203139016164203230056d696e696d203231"
    "0376656e69616d2032320f717569732032330d6e6f73747275642032341b6578"
    "65726369746174696f6e2032350d756c6c616d636f2032360d6c61626f726973"
    "2032370f6e6973692032380175742032390d616c697175697020333001657820"
    "333101656120333237636f6d6d6f646f0a636f6e7365717561742033330f4475"
    "69732033340f6175746520333505697275726520333605646f6c6f7220333701"
    "696e2033383b726570726568656e646572697420333901696e2034300b766f6c"
    "7570746174652034310576656c69742034320f657373652034330363696c6c75"
    "6d20343403646f6c6f726520343501657520343603667567696174203437056e"
    "756c6c612034385b70617269617475720a4578636570746575722034390f7369"
    "6e74203530176f636361656361742035310b637570696461746174203532076e"
    "6f6e2035331770726f6964656e742035340f73756e7420353501696e20353605"
    "63756c7061203537077175692035380d6f666669636961203539176465736572"
    "756e74203630036d6f6c6c69742036310f616e696d2036320169642036330765"
    "73742036340d6c61626f72756d203635")};

TEST_CASE("Decompressor: lorem ipsum next_uncompressed", "[silkworm][node][seg][decompressor]") {
    TemporaryFile tmp_file{};
    tmp_file.write(kLoremIpsumDict);
    Decompressor decoder{tmp_file.path()};

    {
        size_t i{0};
        auto it = decoder.make_iterator();
        while (it.has_next() && i < kLoremIpsumWords.size()) {
            if (i % 2 == 0) {
                it.skip_uncompressed();
            } else {
                const std::string word_plus_index{kLoremIpsumWords[i] + " " + std::to_string(i)};
                const Bytes expected_word{word_plus_index.cbegin(), word_plus_index.cend()};
                ByteView decoded_word;
                it.next_uncompressed(decoded_word);
                CHECK(decoded_word == expected_word);
            }
            ++i;
        }
        CHECK_FALSE(it.has_next());
        CHECK(i == kLoremIpsumWords.size());
    }
}

TEST_CASE("Decompressor: lorem ipsum next", "[silkworm][node][seg][decompressor]") {
    TemporaryFile tmp_file{};
    tmp_file.write(kLoremIpsumDict);
    Decompressor decoder{tmp_file.path()};

    {
        size_t i{0};
        auto it = decoder.make_iterator();
        while (it.has_next() && i < kLoremIpsumWords.size()) {
            if (i % 2 == 0) {
                it.skip_compressed();
            } else {
                const std::string word_plus_index{kLoremIpsumWords[i] + " " + std::to_string(i)};
                const Bytes expected_word{word_plus_index.cbegin(), word_plus_index.cend()};
                Bytes decoded_word;
                it.next_compressed(decoded_word);
                CHECK(decoded_word == expected_word);
            }
            ++i;
        }
        CHECK_FALSE(it.has_next());
        CHECK(i == kLoremIpsumWords.size());
    }
}

TEST_CASE("Decompressor: lorem ipsum has_prefix", "[silkworm][node][seg][decompressor]") {
    TemporaryFile tmp_file{};
    tmp_file.write(kLoremIpsumDict);
    Decompressor decoder{tmp_file.path()};

    {
        size_t i{0};
        auto it = decoder.make_iterator();
        while (it.has_next() && i < kLoremIpsumWords.size()) {
            const std::string word_plus_index{kLoremIpsumWords[i] + " " + std::to_string(i)};
            const Bytes expected_word{word_plus_index.cbegin(), word_plus_index.cend()};
            CHECK(it.has_prefix(expected_word.substr(0, expected_word.size() / 2)));
            if (!expected_word.empty()) {
                Bytes modified_word{expected_word};
                ++modified_word[expected_word.size() - 1];
                CHECK(!it.has_prefix(modified_word));
            }
            it.skip_compressed();
            ++i;
        }
        CHECK(i == kLoremIpsumWords.size());
    }
}

}  // namespace silkworm::snapshots
