// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <filesystem>
#include <fstream>

#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/db/datastore/snapshots/segment/seg/common/varint.hpp>
#include <silkworm/db/datastore/snapshots/snapshot_repository.hpp>
#include <silkworm/infra/test_util/temporary_file.hpp>

namespace silkworm::snapshots::test_util {

using snapshots::SnapshotPath;

//! Big-endian encoder
inline size_t encode_big_endian(uint64_t value, Bytes& output) {
    const size_t old_size = output.size();
    output.resize(old_size + sizeof(uint64_t));
    endian::store_big_u64(output.data() + old_size, value);
    return output.size();
}

//! Varint encoder
inline size_t encode_varint(uint64_t value, Bytes& output) {
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
    uint64_t compute_patterns_size() const {
        uint64_t patterns_size{0};
        Bytes temp_buffer{};
        for (const auto& pattern : patterns) {
            patterns_size += encode_varint(pattern.depth, temp_buffer);
            patterns_size += encode_varint(pattern.data.size(), temp_buffer);
            patterns_size += pattern.data.size();
        }
        return patterns_size;
    }

    uint64_t compute_positions_size() const {
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
    TemporarySnapshotFile(
        const std::filesystem::path& tmp_dir,
        const std::string& filename,
        const SnapshotHeader& header = {},
        const SnapshotBody& body = {})
        : TemporarySnapshotFile{
              parse_path_or_die(tmp_dir, filename),
              encode_header_and_body(header, body),
          } {}

    TemporarySnapshotFile(
        const std::filesystem::path& tmp_dir,
        const std::string& filename,
        ByteView data)
        : TemporarySnapshotFile{
              parse_path_or_die(tmp_dir, filename),
              data,
          } {}

    TemporarySnapshotFile(
        SnapshotPath path,
        ByteView data)
        : file_{path.path().parent_path(), path.filename()},
          path_{std::move(path)} {
        file_.write(data);
    }

    const SnapshotPath& path() const { return path_; }
    const std::filesystem::path& fs_path() const { return file_.path(); }

  private:
    static Bytes encode_header_and_body(
        const SnapshotHeader& header,
        const SnapshotBody& body) {
        Bytes data;
        header.encode(data);
        body.encode(data);
        return data;
    }

    static SnapshotPath parse_path_or_die(
        const std::filesystem::path& tmp_dir,
        const std::string& filename) {
        auto path = SnapshotPath::parse(tmp_dir / filename);
        if (!path)
            throw std::runtime_error{"TemporarySnapshotFile: invalid snapshot filename: " + filename};
        return std::move(*path);
    }

    silkworm::test_util::TemporaryFile file_;
    SnapshotPath path_;
};

//! HelloWorld snapshot file: it contains just one word: "hello, world" w/o any patterns
class HelloWorldSnapshotFile : public TemporarySnapshotFile {
  public:
    explicit HelloWorldSnapshotFile(const std::filesystem::path& tmp_dir, const std::string& filename)
        : TemporarySnapshotFile{tmp_dir, filename, kHeader, kBody} {}

  private:
    static inline const SnapshotHeader kHeader{
        .words_count = 1,  // number of non-empty words
        .empty_words_count = 0,
        .patterns = std::vector<SnapshotPattern>{},  // zero patterns
        .positions = std::vector<SnapshotPosition>{
            {1, 0},  // 1: depth 0: value
            {1, 13}  // 1: depth 13: unencoded data length (including position encoding)
        }};
    static inline const SnapshotBody kBody{
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

inline const BlockNumRange kSampleSnapshotBlockRange{1'500'012, 1'500'014};

//! Sample Headers snapshot file: it contains the mainnet block headers in range [1'500'012, 1'500'013]
//! At least 2 blocks are required because RecSplit key set must have at least *2* keys
class SampleHeaderSnapshotFile : public TemporarySnapshotFile {
  public:
    static constexpr const char* kHeadersSnapshotFileName{"v1-001500-001501-headers.seg"};

    //! This ctor lets you pass any snapshot content and is used to produce broken snapshots
    SampleHeaderSnapshotFile(const std::filesystem::path& tmp_dir, std::string_view hex)
        : TemporarySnapshotFile{tmp_dir, kHeadersSnapshotFileName, *from_hex(hex)} {}

    BlockNumRange block_num_range() const { return kSampleSnapshotBlockRange; }

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
    static constexpr const char* kBodiesSnapshotFileName{"v1-001500-001501-bodies.seg"};

    //! This ctor lets you pass any snapshot content and is used to produce broken snapshots
    SampleBodySnapshotFile(const std::filesystem::path& tmp_dir, std::string_view hex)
        : TemporarySnapshotFile{tmp_dir, kBodiesSnapshotFileName, *from_hex(hex)} {}

    BlockNumRange block_num_range() const { return kSampleSnapshotBlockRange; }

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
    static constexpr const char* kTransactionsSnapshotFileName{"v1-001500-001501-transactions.seg"};

    //! This ctor lets you pass any snapshot content and is used to produce broken snapshots
    SampleTransactionSnapshotFile(const std::filesystem::path& tmp_dir, std::string_view hex)
        : TemporarySnapshotFile{tmp_dir, kTransactionsSnapshotFileName, *from_hex(hex)} {}

    BlockNumRange block_num_range() const { return kSampleSnapshotBlockRange; }

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

//! Sample Accounts KV segment file generated using Erigon aggregator_test.go:generateKV
//! with parameters: keySize=52, M=30, valueSize=180, keyCount=10
class SampleAccountsDomainSegmentFile : public TemporarySnapshotFile {
  public:
    //! This ctor lets you pass any snapshot content and is used to produce broken snapshots
    SampleAccountsDomainSegmentFile(const std::filesystem::path& tmp_dir, std::string_view hex)
        : TemporarySnapshotFile{tmp_dir, "v1-accounts.0-1024.kv", *from_hex(hex)} {}

    //! This ctor captures the correct sample snapshot content once for all
    explicit SampleAccountsDomainSegmentFile(const std::filesystem::path& tmp_dir)
        : SampleAccountsDomainSegmentFile(
              tmp_dir,
              "0000000000000014"  // WC = 20
              "0000000000000000"  // EWC = 0
              "0000000000000000"  // PaTS = 0
              "000000000000001a"  // PoTS = 26
              "01000235054d05ad0105430553057b05170630060e06a1010651010194fdc2fa"
              "2ffcc041d3ff12045b73c86e4ff95ff662a5eee82abdf44a2d0b75fb180daf48"
              "a79ee0b10d3946000000000000000007e285ece1511455780875d64ee2d3d0d0"
              "de6bf8f9b44ce85ff044c6b1f83b8e883bbf857aab99c5b252c7429c32f3a8ae"
              "b79ef856f659c18f0dcecc77c75e7a81bfde275f67cfe242cf3cc354f3ede2d6"
              "becc4ea3ae5e88526a9f4a578bcb9ef2d4a65314768d6d299761ea9e4f5aa6ae"
              "c3fc78c6aae081ac8120011c0cb96ad322d62282295fbfe11e26a433076db5c1"
              "444c3a34d32a5c4a7ffbe8d181f7ed3b8cfe904f93f8f0000000000000000217"
              "2e046410f44bc4b0f3f03a0d06820a30f257f8114130015056b55f92a355db76"
              "5adc8d3df88eb93d527f7f7ec869a75703ba86d4b36110e9a044593c966815d1"
              "53665300000000000000093ff3e6b0f04035ef9419883e03c08e2d753b08c909"
              "0aabf175fdb63e8cf9a5f0783704c741c195157626401d949eaa6dbd04d7ade5"
              "749eab5470bf5e9c18cc79dda4e12efe564ecb8a4019e1c41f2d82170158c6db"
              "3262670649f3bc97d9a2316735ede682a5dfe6f1a011fbc98ad0fbe790003c01"
              "e8e9967703af665e9f00000000000000041374aafe8a0d3e0515dd4650cf5117"
              "2b81248bcb7f969e400b6c5b127768b1c412fae98cf57631cf37033b4b4aba7d"
              "7ed319ba147249c908ac70d1c406dade0e828eb6ba0dcaa88285543e10213c64"
              "3fc8603b5860236670babcad0bd7f4c4190e323623a868d1eae1769f40a26631"
              "431b3bd5215605d2086fead499ac63a4653d12283d56019c3795a98a126d09cf"
              "cbe36cdcc93788a5409f8b6e42c2dd83aa46611852ad0b5028775c7716900167"
              "8ac04586c1e3c9342c8b8055c466d886441d259906d69acd894b968ae9f0eb9d"
              "965ce6a4693c4ebe88150100000000000000031b7e5cda7b6cba6891d616bd68"
              "6c37b834613ac8baa22c008ffe688352734ae4e3f1217acd5f83270814301867"
              "b5d06711b238001c7957b27719ce3f3188dfe57deebf6f82595a10f7bb562ca0"
              "4d5c3d2794290171a420834383661801bb0bfd8e6c140071db1eb2f7a18194f1"
              "a045a94c078835c75dff2f3e836180baad9e9500000000000000060f98f8c201"
              "aec254a0e36476b2eeb124fdc6afc1b7d809c5e08b5e0e845aaf9b6c3957e95a"
              "b4aa8e107cdb873f2dac52017f16c4d5ac8760768a715e4669cb840c25317f9a"
              "368774e506341afb46503e28e92e51bd7f7d4b53b9023d560000000000000007"
              "1fbc45ff64bb2bf14d4051a7604b28bad44d98bfe30e54ebc07fa45f62aabe39"
              "5cc94fa0a0f246b5d28b2e3f6deb2990187058e4bfd2d1640653fc38a30b0f83"
              "231a965b413b0f26927e0d032e830b732bdeb3094cb1a5fa6dec9f06375ea25f"
              "e57c2853ea09320ac8803976eacaa095c02f869fd7dc31072475940c3751d562"
              "83c49e2fefd41df676bdcb5855a0470efd2dab7a72cc5e5f39ff7eea0f433a9f"
              "e701b6854e05b377241e73a883dd77aff0302c6da8665c42341dda4adaea595a"
              "b1895f9652489dd2ceb49c24743000000000000000050b662c9c66b878290519"
              "0f1e1635b63e34878d3f246fadfce344e74ef813090f8030bcd525ac10653ff1"
              "82e00120f7e1f796fa0fc16ba7bb90be2a33e87c3d60ab628401b6a675bc2ac5"
              "0cd218c009e21f910f9ddb09a0d059c4cd7d2ca65a2349df7a867dbedd81e9d4"
              "891619c83c4200000000000000082fcaed9130ab1dd4cc2d8147a15901c720ef"
              "cd6cea84b6925e607be063716f96ddcdd01d75045c3f000f8a796bce6c512c38"
              "01aacaeedfad5b5066000000000000000103b8b7c1965d9181251b7c9c9ca520"
              "5afc16a236a2efcdd2d12d2a79d074a8280ae9439eb0d6aeca0823ae02d67d86"
              "6ac2c4fe4a725053da119b9d4f515140a2d7239c40b45ac3950d941fc4fe") {}
};

//! Sample Accounts existence index file generated using Erigon aggregator_test.go:generateKV
class SampleAccountsDomainExistenceIndexFile : public TemporarySnapshotFile {
  public:
    //! This ctor lets you pass any snapshot content and is used to produce broken snapshots
    SampleAccountsDomainExistenceIndexFile(const std::filesystem::path& tmp_dir, std::string_view hex)
        : TemporarySnapshotFile{tmp_dir, "v1-accounts.0-1024.kvei", *from_hex(hex)} {}

    //! This ctor captures the correct sample snapshot content once for all
    explicit SampleAccountsDomainExistenceIndexFile(const std::filesystem::path& tmp_dir)
        : SampleAccountsDomainExistenceIndexFile(
              tmp_dir,
              "00000000000000007630320a03000000000000000a0000000000000060000000"
              "00000000cc6bab7ea3f92b90703c27812255d1e5c7ffdf994578ee3c428838c0"
              "009022a78b200087000000005fcb40babe887b416444f783dca9c3826bd676ef"
              "32c645a280eb7ce40acab41e296fc6b9bafcfa2edd3b2dc83b0994ab") {}
};

//! Sample Accounts B-tree index file generated using Erigon aggregator_test.go:generateKV
class SampleAccountsDomainBTreeIndexFile : public TemporarySnapshotFile {
  public:
    //! This ctor lets you pass any snapshot content and is used to produce broken snapshots
    SampleAccountsDomainBTreeIndexFile(const std::filesystem::path& tmp_dir, std::string_view hex)
        : TemporarySnapshotFile{tmp_dir, "v1-accounts.0-1024.bt", *from_hex(hex)} {}

    //! This ctor captures the correct sample snapshot content once for all
    explicit SampleAccountsDomainBTreeIndexFile(const std::filesystem::path& tmp_dir)
        : SampleAccountsDomainBTreeIndexFile(
              tmp_dir,
              "000000000000000900000000000004e300cc0b241b9d9f080000000000000000"
              "2922891400000000000000000000000000000000000000000000000000000000"
              "0000000000000001000000000000000000340194fdc2fa2ffcc041d3ff12045b"
              "73c86e4ff95ff662a5eee82abdf44a2d0b75fb180daf48a79ee0b10d39460000"
              "000000000000") {}
};

}  // namespace silkworm::snapshots::test_util
