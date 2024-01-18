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

#include <benchmark/benchmark.h>

#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/node/snapshots/huffman/decompressor.hpp>
#include <silkworm/node/snapshots/index.hpp>
#include <silkworm/node/test/files.hpp>
#include <silkworm/node/test/snapshots.hpp>

namespace silkworm::snapshots {

const Bytes kLoremIpsumDict{*from_hex(
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

static void open_snapshot(benchmark::State& state) {
    test::TemporaryFile tmp_file{};
    tmp_file.write(kLoremIpsumDict);
    for ([[maybe_unused]] auto _ : state) {
        huffman::Decompressor decoder{tmp_file.path()};
        decoder.open();
    }
}
BENCHMARK(open_snapshot);

static void build_header_index(benchmark::State& state) {
    const auto tmp_dir = TemporaryDirectory::get_unique_temporary_path();
    std::filesystem::create_directories(tmp_dir);
    snapshots::SnapshotSettings settings{tmp_dir};
    snapshots::SnapshotRepository repository{settings};

    // These sample snapshot files just contain data for block range [1'500'012, 1'500'013], hence current snapshot
    // file name format is not sufficient to support them (see checks commented out below)
    test::SampleHeaderSnapshotFile header_snapshot{tmp_dir};
    test::SampleBodySnapshotFile body_snapshot{tmp_dir};
    test::SampleTransactionSnapshotFile txn_snapshot{tmp_dir};

    for ([[maybe_unused]] auto _ : state) {
        test::SampleHeaderSnapshotPath header_snapshot_path{header_snapshot.path()};  // necessary to tweak the block numbers
        snapshots::HeaderIndex header_index{header_snapshot_path};
        header_index.build();
    }
}
BENCHMARK(build_header_index);

static void build_body_index(benchmark::State& state) {
    const auto tmp_dir = TemporaryDirectory::get_unique_temporary_path();
    std::filesystem::create_directories(tmp_dir);
    snapshots::SnapshotSettings settings{tmp_dir};
    snapshots::SnapshotRepository repository{settings};

    // These sample snapshot files just contain data for block range [1'500'012, 1'500'013], hence current snapshot
    // file name format is not sufficient to support them (see checks commented out below)
    test::SampleBodySnapshotFile body_snapshot{tmp_dir};

    for ([[maybe_unused]] auto _ : state) {
        test::SampleBodySnapshotPath body_snapshot_path{body_snapshot.path()};  // necessary to tweak the block numbers
        snapshots::BodyIndex body_index{body_snapshot_path};
        body_index.build();
    }
}
BENCHMARK(build_body_index);

static void build_tx_index(benchmark::State& state) {
    const auto tmp_dir = TemporaryDirectory::get_unique_temporary_path();
    std::filesystem::create_directories(tmp_dir);
    snapshots::SnapshotSettings settings{tmp_dir};
    snapshots::SnapshotRepository repository{settings};

    // These sample snapshot files just contain data for block range [1'500'012, 1'500'013], hence current snapshot
    // file name format is not sufficient to support them (see checks commented out below)
    test::SampleBodySnapshotFile body_snapshot{tmp_dir};
    test::SampleTransactionSnapshotFile txn_snapshot{tmp_dir};

    for ([[maybe_unused]] auto _ : state) {
        test::SampleBodySnapshotPath body_snapshot_path{body_snapshot.path()};  // necessary to tweak the block numbers
        snapshots::BodyIndex body_index{body_snapshot_path};
        body_index.build();

        test::SampleTransactionSnapshotPath txn_snapshot_path{txn_snapshot.path()};  // necessary to tweak the block numbers
        snapshots::TransactionIndex txn_index{txn_snapshot_path};
        txn_index.build();
    }
}
BENCHMARK(build_tx_index);

static void reopen_folder(benchmark::State& state) {
    test_util::SetLogVerbosityGuard guard{log::Level::kNone};
    const auto tmp_dir = TemporaryDirectory::get_unique_temporary_path();
    std::filesystem::create_directories(tmp_dir);
    snapshots::SnapshotSettings settings{tmp_dir};
    snapshots::SnapshotRepository repository{settings};

    // These sample snapshot files just contain data for block range [1'500'012, 1'500'013], hence current snapshot
    // file name format is not sufficient to support them (see checks commented out below)
    test::SampleHeaderSnapshotFile header_snapshot{tmp_dir};
    test::SampleBodySnapshotFile body_snapshot{tmp_dir};
    test::SampleTransactionSnapshotFile txn_snapshot{tmp_dir};

    test::SampleHeaderSnapshotPath header_snapshot_path{header_snapshot.path()};  // necessary to tweak the block numbers
    snapshots::HeaderIndex header_index{header_snapshot_path};
    header_index.build();

    test::SampleBodySnapshotPath body_snapshot_path{body_snapshot.path()};  // necessary to tweak the block numbers
    snapshots::BodyIndex body_index{body_snapshot_path};
    body_index.build();

    test::SampleTransactionSnapshotPath txn_snapshot_path{txn_snapshot.path()};  // necessary to tweak the block numbers
    snapshots::TransactionIndex txn_index{txn_snapshot_path};
    txn_index.build();

    for ([[maybe_unused]] auto _ : state) {
        repository.reopen_folder();
    }
}
BENCHMARK(reopen_folder);

}  // namespace silkworm::snapshots
