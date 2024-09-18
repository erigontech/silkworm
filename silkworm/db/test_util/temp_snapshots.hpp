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
#include <silkworm/db/snapshots/seg/common/varint.hpp>
#include <silkworm/db/snapshots/snapshot_repository.hpp>
#include <silkworm/infra/test_util/temporary_file.hpp>

namespace silkworm::snapshots::test_util {

using snapshots::SnapshotPath;
using snapshots::SnapshotType;

//! Big-endian encoder
inline std::size_t encode_big_endian(uint64_t value, Bytes& output) {
    const std::size_t old_size = output.size();
    output.resize(old_size + sizeof(uint64_t));
    endian::store_big_u64(output.data() + old_size, value);
    return output.size();
}

//! Varint encoder
inline std::size_t encode_varint(uint64_t value, Bytes& output) {
    Bytes encoded;
    seg::varint::encode(encoded, value);
    output.append(encoded);
    return encoded.size();
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
        encode_big_endian(words_count, output);
        encode_big_endian(empty_words_count, output);
        encode_big_endian(compute_patterns_size(), output);
        for (const auto& pattern : patterns) {
            encode_varint(pattern.depth, output);
            encode_varint(pattern.data.size(), output);
            output.append(pattern.data.cbegin(), pattern.data.cend());
        }
        encode_big_endian(compute_positions_size(), output);
        for (const auto& position : positions) {
            encode_varint(position.depth, output);
            encode_varint(position.value, output);
        }
    }

  private:
    [[nodiscard]] uint64_t compute_patterns_size() const {
        uint64_t patterns_size{0};
        Bytes temp_buffer{};
        for (const auto& pattern : patterns) {
            patterns_size += encode_varint(pattern.depth, temp_buffer);
            patterns_size += encode_varint(pattern.data.size(), temp_buffer);
            patterns_size += pattern.data.size();
        }
        return patterns_size;
    }

    [[nodiscard]] uint64_t compute_positions_size() const {
        uint64_t positions_size{0};
        Bytes temp_buffer{};
        for (const auto& position : positions) {
            positions_size += encode_varint(position.depth, temp_buffer);
            positions_size += encode_varint(position.value, temp_buffer);
        }
        return positions_size;
    }
};

struct SnapshotBody {
    Bytes data;

    void encode(Bytes& output) const {
        output.append(data.cbegin(), data.cend());
    }
};

//! Temporary snapshot file
class TemporarySnapshotFile {
  public:
    TemporarySnapshotFile(const std::filesystem::path& tmp_dir,
                          const std::string& filename,
                          const SnapshotHeader& header = {},
                          const SnapshotBody& body = {})
        : file_(tmp_dir, filename) {
        Bytes data{};
        header.encode(data);
        body.encode(data);
        file_.write(data);
    }

    TemporarySnapshotFile(const std::filesystem::path& tmp_dir, const std::string& filename, ByteView data)
        : file_(tmp_dir, filename) {
        file_.write(data);
    }

    const std::filesystem::path& path() const { return file_.path(); }

  private:
    silkworm::test_util::TemporaryFile file_;
};

//! HelloWorld snapshot file: it contains just one word: "hello, world" w/o any patterns
class HelloWorldSnapshotFile : public TemporarySnapshotFile {
  public:
    explicit HelloWorldSnapshotFile(const std::filesystem::path& tmp_dir, const std::string& filename)
        : TemporarySnapshotFile{tmp_dir, filename, kHeader, kBody} {}

  private:
    inline static const SnapshotHeader kHeader{
        .words_count = 1,  // number of non-empty words
        .empty_words_count = 0,
        .patterns = std::vector<SnapshotPattern>{},  // zero patterns
        .positions = std::vector<SnapshotPosition>{
            {1, 0},  // 1: depth 0: value
            {1, 13}  // 1: depth 13: unencoded data length (including position encoding)
        }};
    inline static const SnapshotBody kBody{
        *from_hex("0168656C6C6F2C20776F726C64")  // 0x01: position 0x68656C6C6F2C20776F726C64: "hello, world"
    };
};

// SampleBodySnapshotFile + SampleBodySnapshotFile + SampleTransactionSnapshotFile
// Sample snapshot files for mainnet blocks 1'500'013 containing 1 tx: https://etherscan.io/block/1500013

// Legend:
// - WC: number of non-empty words
// - EWC: number of empty words
// - PaT (Pattern Table): encoded table of patterns
// - PoT (Position Table): encoded table of positions
// - PaTS (PaT Size): size of pattern table in bytes
// - PoTS (PoT Size): size of position table in bytes

//! Sample Headers snapshot file: it contains the mainnet block headers in range [1'500'012, 1'500'013]
//! At least 2 blocks are required because RecSplit key set must have at least *2* keys
class SampleHeaderSnapshotFile : public TemporarySnapshotFile {
  public:
    static constexpr const char* kHeadersSnapshotFileName{"v1-001500-001500-headers.seg"};

    //! This ctor lets you pass any snapshot content and is used to produce broken snapshots
    SampleHeaderSnapshotFile(const std::filesystem::path& tmp_dir, std::string_view hex)
        : TemporarySnapshotFile{tmp_dir, kHeadersSnapshotFileName, *from_hex(hex)} {}

    //! This ctor captures the correct sample snapshot content once for all
    explicit SampleHeaderSnapshotFile(const std::filesystem::path& tmp_dir)
        : SampleHeaderSnapshotFile(
              tmp_dir,
              "0000000000000002"                                                  // WC = 2
              "0000000000000000"                                                  // EWC = 0
              "0000000000000152"                                                  // PaTS = 338
              "0320A00000000000000000000000000000000000000000000000000000000000"  // PaT = 0x0320...
              "0000038001B90100000000000000000000000000000000000000000000000000"
              "0000000000000000000000000000000000000000000000000000000000000000"
              "0000000000000000000000000000000000000000000000000000000000000000"
              "0000000000000000000000000000000000000000000000000000000000000000"
              "0000000000034000000000000000000000000000000000000000000000000000"
              "00000000000000A0000000000000000000000000000000000000000000000000"
              "0000000000000004200000000000000000000000000000000000000000A00000"
              "0000000000000000000440000000000000A00000000000000000000000000000"
              "000000000000000000000000000000000000A000000000000000000000000000"
              "000000000000000000000001050000000000"
              "000000000000001A"                                                  // PoTS = 26
              "04F503044304BF010400048201040F059C040542052605290106"              // PoT = 0x04F5...
              "5068EA5E96F2FFFFFFFFFF7F85CBC2F901F0A000940000808316E36C80808080"  // Header 1'500'012
              "00880000008628FFFFFFFFFFFF67"
              "BEF90217A048A486D69A07E99ED6997EB0F9B8795E4E7D07C0CE5B8EE8E139D6"  // Header 1'500'013 (Hash 1st byte + RLP)
              "53FD1B01C3A07117CFC18FF9765FB04A0C223722D1CFD20A06E5D7A88778F9F6"
              "6A2207B0638B94EA674FDDE714FD979DE3EDF0F56AA9716B898EC8A0AC26FC90"
              "B79CD9304F03C925208E377D4E6E4B229EDE56EB1728851E656791BCA0BC18A8"
              "09C2AB84E0870C0BE8DE331E3E0498E31B22CDEB95E07F23A5C7F77F40A0C856"
              "DB90A6C30A0264858960231C4A3F78F557EA83EA4D7EC260C691B08505230086"
              "1FAD3D458F3E8316E36D8347E7C4825208845733A90798D78301040084476574"
              "6887676F312E352E31856C696E7578A0799895E28A837BBDF28B8ECF5FC0E625"
              "1398ECB0FFC7FF5BBB457C21B14CE982888698762012B46FEF") {}
};

//! Sample Bodies snapshot file: it contains the mainnet block bodies in range [1'500'012, 1'500'013]
class SampleBodySnapshotFile : public TemporarySnapshotFile {
  public:
    static constexpr const char* kBodiesSnapshotFileName{"v1-001500-001500-bodies.seg"};

    //! This ctor lets you pass any snapshot content and is used to produce broken snapshots
    SampleBodySnapshotFile(const std::filesystem::path& tmp_dir, std::string_view hex)
        : TemporarySnapshotFile{tmp_dir, kBodiesSnapshotFileName, *from_hex(hex)} {}

    //! This empty ctor captures the correct sample snapshot content once for all
    explicit SampleBodySnapshotFile(const std::filesystem::path& tmp_dir)
        : SampleBodySnapshotFile(
              tmp_dir,
              "0000000000000002"  // WC = 2
              "0000000000000000"  // EWC = 0
              "0000000000000000"  // PaTS = 0
              "0000000000000007"  // PoTS = 7
              "0100020802A404"    // PoT = 0x01...04
              "01"
              "C6837004CE09C0"  // Body 1'500'012
              "03"
              "F90220837004D703F90218F90215A04930C7E9157B97E6A68AB4D26F4EC99268"  // Body 1'500'013
              "94635A4A89BBEFECD96D62C83C1D5DA01DCC4DE8DEC75D7AAB85B567B6CCD41A"
              "D312451B948A7413F0A142FD40D4934794EA674FDDE714FD979DE3EDF0F56AA9"
              "716B898EC8A0813E0EF24189E66F4A5D5A123DD39D1D1529E48C6F7FE6290E0C"
              "917EB1717B4FA056E81F171BCC55A6FF8345E692C0F86E5B48E01B996CADC001"
              "622FB5E363B421A056E81F171BCC55A6FF8345E692C0F86E5B48E01B996CADC0"
              "01622FB5E363B421B90100000000000000000000000000000000000000000000"
              "0000000000000000000000000000000000000000000000000000000000000000"
              "0000000000000000000000000000000000000000000000000000000000000000"
              "0000000000000000000000000000000000000000000000000000000000000000"
              "0000000000000000000000000000000000000000000000000000000000000000"
              "0000000000000000000000000000000000000000000000000000000000000000"
              "0000000000000000000000000000000000000000000000000000000000000000"
              "0000000000000000000000000000000000000000000000000000000000000000"
              "0000000000000000000000861FB1346966098316E36B8347E7C480845733A8DF"
              "98D783010400844765746887676F312E352E31856C696E7578A028FB78C93A8C"
              "6BF6B9A353BD3566DE6861EAAC19C0ED1B663CBAAEE0CFE6E70A88C7E9D99815"
              "48460F") {}
};

//! Sample Transactions snapshot file: it contains the mainnet block transactions in range [1'500'012, 1'500'013]
class SampleTransactionSnapshotFile : public TemporarySnapshotFile {
  public:
    static constexpr const char* kTransactionsSnapshotFileName{"v1-001500-001500-transactions.seg"};

    //! This ctor lets you pass any snapshot content and is used to produce broken snapshots
    SampleTransactionSnapshotFile(const std::filesystem::path& tmp_dir, std::string_view hex)
        : TemporarySnapshotFile{tmp_dir, kTransactionsSnapshotFileName, *from_hex(hex)} {}

    //! This empty ctor captures the correct sample snapshot content once for all
    explicit SampleTransactionSnapshotFile(const std::filesystem::path& tmp_dir)
        : SampleTransactionSnapshotFile(
              tmp_dir,
              "000000000000000C"                              // WC = 12
              "0000000000000004"                              // EWC = 4
              "0000000000000000"                              // PaTS = 0
              "0000000000000016"                              // PoTS = 22
              "010004E60304850104E5020487010301048801048401"  // PoT = 0x01...01
              "0309"
              "3DE6BF8FE3E608CC04681B3DFC8B2D52AB94C23DB7F86D018504E3B292008252"  // Txn position 0 block 1'500'012 START
              "0894BB9BC244D798123FDE783FCC1C72D3BB8C1894138902292B2AD00B120000"
              "801CA0F5D7EB932991DC38FB5A3ED2ABCC71C2ABFC098BB2A9A25552ABEC2249"
              "A6AAF8A055CAD62B0CD8E2B6154F2EA52D308535EF634D9A207571996754A02E"
              "59DE97C1"  // Txn position 0 block 1'500'012 END
              "0F"
              "0A9C0474E418336FE6779BF5D2875DEA284711E425F86C038504E3B292008255"  // Txn position 1 block 1'500'012 START
              "F094BB9BC244D798123FDE783FCC1C72D3BB8C189413884563918244F4000080"
              "1CA05FED9736B73FADD09E07BE4836AA45D77D6C1B91F3026E0941F11BF3DE40"
              "6624A00F1A573F9887A33ED2B515CB0931D827BDB89FA816800ACEE6FB06E618"
              "70F9DB"  // Txn position 1 block 1'500'012 END
              "07"
              "134BB96091EE9D802ED039C4D1A5F6216F90F81B01F870830137DE8504A817C8"  // Txn position 2 block 1'500'012 START
              "0083015F90942B9F67024DC91DEBAB6A322D27201F5F80F6B06A8844B1EEC616"
              "2F0000801CA0B82395812DA2B520E9094FEE335FE7720F76ACE9667884F2C2FA"
              "6F87E840307FA05C591CE13EEC49BDE11371D0EFE605D2CF97D2053BBDC96213"
              "14C394B2E9D67E"  // Txn position 2 block 1'500'012 END
              "05"
              "DBAC4361F56C82ED59D533D45129F407015D84702AF9014C820BA78504A817C8"  // Txn position 3 block 1'500'012 START
              "0083124F809441F274C0023F83391DE4E0733C609DF5A124C3D480B8E490FA33"
              "7D00000000000000000000000000000000000000000000000000000000000000"
              "6000000000000000000000000000000000000000000000000000038D7EA4C680"
              "0000000000000000000000000001A23FD30AABF5AD53BAB3093DCD4948E15CEC"
              "8000000000000000000000000000000000000000000000000000000000000000"
              "50040000001981112F120482B107DCFF689E37324FB91E567A3C251D00000000"
              "00000000001B3C3DC83843E88150721108C66984F528382EAC91CC624D29D5F2"
              "7ABE6CB8D9E3A73357FAA80518551AC446000000000000000000000000000000"
              "001BA0A6764120647DFB4C58E4A977778FA3B5464EF0E64D2433E8079098131A"
              "51F317A0105ACC9977815A9BC8A32A7DF9D0AECA6560A09FE89DC14EE1A06D84"
              "67016002"  // Txn position 3 block 1'500'012 END
              "01"
              "A190384D665F5687BE20FA3EFC029939D249F0570CF901CD8260808504A817C8"  // Txn position 4 block 1'500'012 START
              "008307A12094AD62F56A03334B647E55DBDB5B8642C24605A80101B901643ED4"
              "86790000000000000000000000009C4EA8D25D6150A8ED2848FC745158AAD926"
              "BF8D000000000000000000000000000000000000000000000000000000005733"
              "A8EF000000000000000000000000000000000000000000000000000000000000"
              "00C0000000000000000000000000000000000000000000000000000000000000"
              "0120000000000000000000000000490C0DD13BFEA5865CA985297CF2BED3F77B"
              "EB5D000000000000000000000000000000000000000000000000000000000000"
              "0001000000000000000000000000000000000000000000000000000000000000"
              "00025D32BF90EAA0D9FEAA1E8B5645E0CE50FD6408E314874BF9959098E76672"
              "18A5080FC06A25EDAE04D6AA529AF072B5AC8EF4524FEEDBF6CD31C52F24D6A8"
              "4A22000000000000000000000000000000000000000000000000000000000000"
              "0001000000000000000000000000000000000000000000000000000000000000"
              "001C1BA0870CD28E900B59D543EF3590B52C3564A24C32EC503CAE8C7EAD2DDB"
              "E9B7DAB6A01B13F942E5442F0F60A2E91010F9B0C54D47DDD156AA8D159CAF35"
              "0CCFC40836"  // Txn position 4 block 1'500'012 END
              "07"
              "889E6316F44BAEEEE5D41A1070516CC5FA47BAF227F8708218E98504A817C800"  // Txn position 5 block 1'500'012 START
              "8303D090947B09B1AD47A7DB257E56963074FCCD35D5414E948902749EA02452"
              "5B2800801BA05128DB834E449BD1C8EF49F33088C6E01DAE3C607C1F36494510"
              "0748F2920B41A059F30995C21D130330C6FAADA406EF7FEFAE898A87792D5540"
              "6BBE66776F43BF"  // Txn position 5 block 1'500'012 END
              "0F"
              "223C3AA259C5AC6BC048CAA54EE0F8D4E8FA7AF25FF86C568504A817C8008256"  // Txn position 6 block 1'500'012 START
              "2294FBB1B73C4F0BDA4F67DCA266CE6EF42F520FBB988846DB2BD5D79CE00080"
              "1CA081F1584E7A96EF0981EC8D906F2FEA9B693AFD3828D7D0707CBEE9248A64"
              "DDE2A07741C894678B0336812A43234B28AA675A7720AC3EC0403D8943C1D3FF"
              "9AE5EB"  // Txn position 6 block 1'500'012 END
              "03"
              "030D"
              "3B68795C4AA09D6F4ED3E5DEDDF8C2AD3049A601DAF86F828F938504A817C800"  // Txn position 0 block 1'500'013 START
              "83015F9094E9AE6EC1117BBFEB89302CE7E632597BC595EFAE880E61A774F297"
              "BB80801CA031131812A9B210CF6033E9420478B72F08251D8C7323DD88BD3A18"
              "0679FA90B5A028A6D676D77923B19506C7AAAE5F1DC2F2244855AABB6672401C"
              "1B55B0D844FF"  // Txn position 0 block 1'500'013 END
              "03") {}
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
        : SampleSnapshotPath(std::move(path), 1'500'012, 1'500'014, SnapshotType::headers) {}
};

//! Sample Body snapshot path injecting custom from/to blocks to override 500'000 block range
class SampleBodySnapshotPath : public SampleSnapshotPath {
  public:
    explicit SampleBodySnapshotPath(std::filesystem::path path)
        : SampleSnapshotPath(std::move(path), 1'500'012, 1'500'014, SnapshotType::bodies) {}
};

//! Sample Transaction snapshot path injecting custom from/to blocks to override 500'000 block range
class SampleTransactionSnapshotPath : public SampleSnapshotPath {
  public:
    explicit SampleTransactionSnapshotPath(std::filesystem::path path)
        : SampleSnapshotPath(std::move(path), 1'500'012, 1'500'014, SnapshotType::transactions) {}
};

}  // namespace silkworm::snapshots::test_util
