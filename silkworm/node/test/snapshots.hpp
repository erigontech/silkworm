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

#include <filesystem>
#include <fstream>

#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/node/snapshot/repository.hpp>
#include <silkworm/node/test/files.hpp>

namespace silkworm::test {

using snapshot::SnapshotPath;
using snapshot::SnapshotType;

//! Big-endian int encoder
template <typename int_t = uint64_t>
std::size_t encode_big_endian(int_t value, Bytes& output) {
    const std::size_t old_size = output.size();
    output.resize(old_size + sizeof(int_t));
    endian::store_big_u64(output.data() + old_size, value);
    return output.size();
}

//! Varint encoder
template <typename int_t = uint64_t>
std::size_t encode_varint(int_t value, Bytes& output) {
    std::size_t varint_size{0};
    while (value > 127) {
        output.push_back(static_cast<uint8_t>(value & 127) | 128);
        value >>= 7;
        ++varint_size;
    }
    output.push_back(static_cast<uint8_t>(value) & 127);
    return ++varint_size;
}

//! Snapshot header encoder
struct SnapshotPattern {
    uint64_t depth;
    Bytes data;
};

struct SnapshotPosition {
    uint64_t depth;
    uint64_t value;
};

struct SnapshotHeader {
    uint64_t words_count;
    uint64_t empty_words_count;
    std::vector<SnapshotPattern> patterns;
    std::vector<SnapshotPosition> positions;

    void encode(Bytes& output) const {
        encode_big_endian<uint64_t>(words_count, output);
        encode_big_endian<uint64_t>(empty_words_count, output);
        encode_big_endian<uint64_t>(compute_patterns_size(), output);
        for (const auto& pattern : patterns) {
            encode_varint<uint64_t>(pattern.depth, output);
            encode_varint<uint64_t>(pattern.data.size(), output);
            output.append(pattern.data.cbegin(), pattern.data.cend());
        }
        encode_big_endian<uint64_t>(compute_positions_size(), output);
        for (const auto& position : positions) {
            encode_varint<uint64_t>(position.depth, output);
            encode_varint<uint64_t>(position.value, output);
        }
    }

  private:
    [[nodiscard]] uint64_t compute_patterns_size() const {
        uint64_t patterns_size{0};
        Bytes temp_buffer{};
        for (const auto& pattern : patterns) {
            patterns_size += encode_varint<uint64_t>(pattern.depth, temp_buffer);
            patterns_size += encode_varint<uint64_t>(pattern.data.size(), temp_buffer);
            patterns_size += pattern.data.size();
        }
        return patterns_size;
    }

    [[nodiscard]] uint64_t compute_positions_size() const {
        uint64_t positions_size{0};
        Bytes temp_buffer{};
        for (const auto& position : positions) {
            positions_size += encode_varint<uint64_t>(position.depth, temp_buffer);
            positions_size += encode_varint<uint64_t>(position.value, temp_buffer);
        }
        return positions_size;
    }
};

struct SnapshotBody {
    Bytes data;
    SnapshotHeader* header{nullptr};

    void encode(Bytes& output) const {
        output.append(data.cbegin(), data.cend());
    }
};

//! Temporary snapshot file
class TemporarySnapshotFile {
  public:
    explicit TemporarySnapshotFile(const SnapshotHeader& header, const SnapshotBody& body = {}) {
        Bytes data{};
        header.encode(data);
        body.encode(data);
        file_.write(data);
    }
    TemporarySnapshotFile(const std::filesystem::path& tmp_dir,
                          const std::string& filename,
                          const SnapshotHeader& header,
                          const SnapshotBody& body = {})
        : file_(tmp_dir, filename) {
        Bytes data{};
        header.encode(data);
        body.encode(data);
        file_.write(data);
    }
    TemporarySnapshotFile(const std::filesystem::path& tmp_dir, const std::string& filename)
        : TemporarySnapshotFile(tmp_dir, filename, {}, {}) {}
    TemporarySnapshotFile(const std::string& filename, ByteView data)
        : file_(TemporaryDirectory::get_os_temporary_path(), filename) {
        file_.write(data);
    }
    TemporarySnapshotFile(const std::string& filename, const SnapshotHeader& header, const SnapshotBody& body = {})
        : TemporarySnapshotFile(TemporaryDirectory::get_os_temporary_path(), filename, header, body) {}
    explicit TemporarySnapshotFile(const std::string& filename)
        : TemporarySnapshotFile(TemporaryDirectory::get_os_temporary_path(), filename, {}, {}) {}

    const std::filesystem::path& path() const { return file_.path(); }

  private:
    test::TemporaryFile file_;
};

//! HelloWorld snapshot file: it contains just one word: "hello, world" w/o any patterns
class HelloWorldSnapshotFile : public TemporarySnapshotFile {
  public:
    explicit HelloWorldSnapshotFile() : TemporarySnapshotFile{kHeader, kBody} {}
    explicit HelloWorldSnapshotFile(const std::filesystem::path& tmp_dir, const std::string& filename)
        : TemporarySnapshotFile{tmp_dir, filename, kHeader, kBody} {}

  private:
    inline static const test::SnapshotHeader kHeader{
        .words_count = 1,  // number of non-empty words
        .empty_words_count = 0,
        .patterns = std::vector<test::SnapshotPattern>{},  // zero patterns
        .positions = std::vector<test::SnapshotPosition>{
            {1, 0},  // 1: depth 0: value
            {1, 13}  // 1: depth 13: unencoded data length (including position encoding)
        }};
    inline static const test::SnapshotBody kBody{
        *from_hex("0168656C6C6F2C20776F726C64")  // 0x01: position 0x68656C6C6F2C20776F726C64: "hello, world"
    };
};

// SampleBodySnapshotFile + SampleBodySnapshotFile + SampleTransactionSnapshotFile
// Sample snapshot files for mainnet block 1'500'013 containing 1 tx: https://etherscan.io/block/1500013

// Legend:
// - WC: number of non-empty words
// - EWC: number of empty words
// - PaT (Pattern Table): encoded table of patterns
// - PoT (Position Table): encoded table of positions
// - PaTS (PaT Size): size of pattern table in bytes
// - PoTS (PoT Size): size of position table in bytes

//! Sample Headers snapshot file: it contains the header for block 1'500'013 on mainnet
//! The main trick here is that this snapshot contains 13 fake empty block headers before the one we're interested in:
//! such 13 are fillers just for positioning the 14-th correctly
class SampleHeaderSnapshotFile : public TemporarySnapshotFile {
  public:
    inline static constexpr const char* kHeadersSnapshotFileName{"v1-001500-001500-headers.seg"};

    //! This ctor lets you pass any snapshot content and is used to produce broken snapshots
    explicit SampleHeaderSnapshotFile(std::string_view hex)
        : TemporarySnapshotFile{kHeadersSnapshotFileName, *from_hex(hex)} {}

    //! This empty ctor captures the correct sample snapshot content once for all
    explicit SampleHeaderSnapshotFile()
        : SampleHeaderSnapshotFile(
              "000000000000000E000000000000000000000000000000CF0340A00000000000"  // WC=14 EWC=0 PaTS=207(0xCF), PaT={03, ...
              "000000000000000000000000000000000000000000000000000000A000000000"  // ...
              "0000000000000000000000000000000000000000000000000000032000000000"  // ...
              "00000000000000000000000000000000A000000000000000000000000320A000"  // ...
              "0000000000000000000000000000000000000000000000000000000000000340"  // ...
              "00000000000000000000000000000000000000000000000000000000000000A0"  // ...
              "0000000000000000000000000000000000000000000000000000000000000000"  // ...
              "01050000000000000000000000001B0445041504F5030407040F0400069C0406"  // ...}, PoTS=27(0x1B), PoT={04, 54, ...
              "C3010524054205260106C4764458C3FFFFFFFFFFFFFFFFFFFFFFFF17F90AF4F9"  // ..., 01, 06}
              "01F0A00094B9010000808316E360808080800088000000C4764458C3FFFFFFFF"
              "FFFFFFFFFFFFFFFF17F90A8EF901F0A00094B9010000808316E3618080808000"
              "88000000C4764458C3FFFFFFFFFFFFFFFFFFFFFFFF17F90A71F901F0A00094B9"
              "010000808316E362808080800088000000C4764458C3FFFFFFFFFFFFFFFFFFFF"
              "FFFF17F90AF3F901F0A00094B9010000808316E363808080800088000000C476"
              "4458C3FFFFFFFFFFFFFFFFFFFFFFFF17F90AC4F901F0A00094B9010000808316"
              "E364808080800088000000C4764458C3FFFFFFFFFFFFFFFFFFFFFFFF17F90AA8"
              "F901F0A00094B9010000808316E365808080800088000000C4764458C3FFFFFF"
              "FFFFFFFFFFFFFFFFFF17F90A4CF901F0A00094B9010000808316E36680808080"
              "0088000000C4764458C3FFFFFFFFFFFFFFFFFFFFFFFF17F90AA2F901F0A00094"
              "B9010000808316E367808080800088000000C4764458C3FFFFFFFFFFFFFFFFFF"
              "FFFFFF17F90A53F901F0A00094B9010000808316E368808080800088000000C4"
              "764458C3FFFFFFFFFFFFFFFFFFFFFFFF17F90A43F901F0A00094B90100008083"
              "16E369808080800088000000C4764458C3FFFFFFFFFFFFFFFFFFFFFFFF17F90A"
              "32F901F0A00094B9010000808316E36A808080800088000000C4764458C3FFFF"
              "FFFFFFFFFFFFFFFFFFFF17F90A3EF901F0A00094B9010000808316E36B808080"
              "800088000000C4764458C3FFFFFFFFFFFFFFFFFFFFFFFF17F90AC2F901F0A000"
              "94B9010000808316E36C80808080008800000086F9FFFFFFFFFFFFFFFFFFFFFF"
              "FF15BEF90217A048A486D69A07E99ED6997EB0F9B8795E4E7D07C0CE5B8EE8E1"
              "39D653FD1B01C3A07117CFC18FF9765FB04A0C223722D1CFD20A06E5D7A88778"
              "F9F66A2207B0638B94EA674FDDE714FD979DE3EDF0F56AA9716B898EC8A0AC26"
              "FC90B79CD9304F03C925208E377D4E6E4B229EDE56EB1728851E656791BCA0BC"
              "18A809C2AB84E0870C0BE8DE331E3E0498E31B22CDEB95E07F23A5C7F77F40A0"
              "C856DB90A6C30A0264858960231C4A3F78F557EA83EA4D7EC260C691B0850523"
              "B9010000861FAD3D458F3E8316E36D8347E7C4825208845733A90798D7830104"
              "00844765746887676F312E352E31856C696E7578A0799895E28A837BBDF28B8E"
              "CF5FC0E6251398ECB0FFC7FF5BBB457C21B14CE982888698762012B46FEF") {}
};

//! Sample Bodies snapshot file: it contains the body for block 1'500'013 on mainnet
//! The main trick here is that this snapshot contains 13 fake empty block bodies before the one we're interested in:
//! such 13 are fillers [all having RLP value c6837004d980c0 for simplicity] just for positioning the 14-th correctly
//! c6837004d980c0: [7'341'273, 0, []] fake empty db::detail::BlockBodyForStorage w/ correct base_txn_id
//! c6837004d901c0: [7'341'273, 1, []] real db::detail::BlockBodyForStorage for block 1'500'013
class SampleBodySnapshotFile : public TemporarySnapshotFile {
  public:
    inline static constexpr const char* kBodiesSnapshotFileName{"v1-001500-001500-bodies.seg"};

    //! This ctor lets you pass any snapshot content and is used to produce broken snapshots
    explicit SampleBodySnapshotFile(std::string_view hex)
        : TemporarySnapshotFile{kBodiesSnapshotFileName, *from_hex(hex)} {}

    //! This empty ctor captures the correct sample snapshot content once for all
    explicit SampleBodySnapshotFile()
        : SampleBodySnapshotFile(
              "000000000000000e000000000000000000000000000000000000000000000004"  // WC=14 EWC=0 PaTS=0 PoTS=4
              "0100010801c6837004d980c001c6837004d980c001c6837004d980c001c68370"  // PoT={{01, 00}, {01, 08}},
              "04d980c001c6837004d980c001c6837004d980c001c6837004d980c001c68370"  // {01, c6837004d980c0}
              "04d980c001c6837004d980c001c6837004d980c001c6837004d980c001c68370"  // ...
              "04d980c001c6837004d980c001c6837004d901c0"                          // {01, c6837004d901c0}
          ) {}
};

//! Sample Transactions snapshot file: it contains the transactions for block 1'500'013 on mainnet (a block with 1 tx)
class SampleTransactionSnapshotFile : public TemporarySnapshotFile {
  public:
    inline static constexpr const char* kTransactionsSnapshotFileName{"v1-001500-001500-transactions.seg"};

    //! This ctor lets you pass any snapshot content and is used to produce broken snapshots
    explicit SampleTransactionSnapshotFile(std::string_view hex)
        : TemporarySnapshotFile{kTransactionsSnapshotFileName, *from_hex(hex)} {}

    //! This empty ctor captures the correct sample snapshot content once for all
    explicit SampleTransactionSnapshotFile()
        : SampleTransactionSnapshotFile(
              "0000000000000001000000000000000000000000000000000000000000000004"  // WC=1 EWC=0 PaTS=0 PoTS=4
              "0100017201f86f828f938504a817c80083015f9094e9ae6ec1117bbfeb89302c"  // PoT={{01, 00}, {01, 72}}, {01, f86f...
              "e7e632597bc595efae880e61a774f297bb80801ca031131812a9b210cf6033e9"  // ...
              "420478b72f08251d8c7323dd88bd3a180679fa90b5a028a6d676d77923b19506"  // ...
              "c7aaae5f1dc2f2244855aabb6672401c1b55b0d844ff"                      // ...44ff}
          ) {}
};

class SampleSnapshotPath : public SnapshotPath {
  public:
    SampleSnapshotPath(std::filesystem::path path, BlockNum from, BlockNum to, SnapshotType type)
        : SnapshotPath(std::move(path), /*.version=*/1, from, to, type) {}
};

//! Sample Header snapshot path injecting custom from/to blocks to override 500'000 block range
class SampleHeaderSnapshotPath : public SampleSnapshotPath {
  public:
    explicit SampleHeaderSnapshotPath(std::filesystem::path path)
        : SampleSnapshotPath(std::move(path), 1'500'000, 1'500'014, SnapshotType::headers) {}
};

//! Sample Body snapshot path injecting custom from/to blocks to override 500'000 block range
class SampleBodySnapshotPath : public SampleSnapshotPath {
  public:
    explicit SampleBodySnapshotPath(std::filesystem::path path)
        : SampleSnapshotPath(std::move(path), 1'500'000, 1'500'014, SnapshotType::bodies) {}
};

//! Sample Transaction snapshot path injecting custom from/to blocks to override 500'000 block range
class SampleTransactionSnapshotPath : public SampleSnapshotPath {
  public:
    explicit SampleTransactionSnapshotPath(std::filesystem::path path)
        : SampleSnapshotPath(std::move(path), 1'500'000, 1'500'014, SnapshotType::transactions) {}
};

}  // namespace silkworm::test
