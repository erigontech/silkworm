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

#include "fork_id.hpp"

#include <limits>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/util.hpp>

namespace silkworm::sentry::eth {

TEST_CASE("ForkId.rlp_encode") {
    CHECK(ForkId(0, 0).rlp_encode() == from_hex("c6840000000080").value());
    CHECK(ForkId(0xdeadbeef, 0xBADDCAFE).rlp_encode() == from_hex("ca84deadbeef84baddcafe").value());
    CHECK(ForkId(std::numeric_limits<uint32_t>::max(), std::numeric_limits<uint64_t>::max()).rlp_encode() == from_hex("ce84ffffffff88ffffffffffffffff").value());
}

TEST_CASE("ForkId.rlp_decode") {
    CHECK(ForkId(0, 0) == ForkId::rlp_decode(from_hex("c6840000000080").value()));
    CHECK(ForkId(0xdeadbeef, 0xBADDCAFE) == ForkId::rlp_decode(from_hex("ca84deadbeef84baddcafe").value()));
    CHECK(ForkId(std::numeric_limits<uint32_t>::max(), std::numeric_limits<uint64_t>::max()) == ForkId::rlp_decode(from_hex("ce84ffffffff88ffffffffffffffff").value()));
}

TEST_CASE("ForkId.hash") {
    CHECK(0xdeadbeef == ForkId::rlp_decode(from_hex("ca84deadbeef84baddcafe").value()).hash());
}

struct ForksExampleSpec {
    uint64_t head_block_num_or_time{0};
    ForkId fork_id;
};

static ForkId fork_id_at(uint64_t head_block_num_or_time, const ChainConfig& chain) {
    REQUIRE(chain.genesis_hash.has_value());
    return ForkId{ByteView{*chain.genesis_hash}, chain.distinct_fork_block_nums(), chain.distinct_fork_times(), head_block_num_or_time};
}

TEST_CASE("ForkId.forks.mainnet") {
    std::vector<ForksExampleSpec> examples = {
        {0, ForkId{0xfc64ec04, 1150000}},              // Unsynced
        {1149999, ForkId{0xfc64ec04, 1150000}},        // Last Frontier block
        {1150000, ForkId{0x97c2c34c, 1920000}},        // First Homestead block
        {1919999, ForkId{0x97c2c34c, 1920000}},        // Last Homestead block
        {1920000, ForkId{0x91d1f948, 2463000}},        // First DAO block
        {2462999, ForkId{0x91d1f948, 2463000}},        // Last DAO block
        {2463000, ForkId{0x7a64da13, 2675000}},        // First Tangerine block
        {2674999, ForkId{0x7a64da13, 2675000}},        // Last Tangerine block
        {2675000, ForkId{0x3edd5b10, 4370000}},        // First Spurious block
        {4369999, ForkId{0x3edd5b10, 4370000}},        // Last Spurious block
        {4370000, ForkId{0xa00bc324, 7280000}},        // First Byzantium block
        {7279999, ForkId{0xa00bc324, 7280000}},        // Last Byzantium block
        {7280000, ForkId{0x668db0af, 9069000}},        // First and last Constantinople, first Petersburg block
        {9068999, ForkId{0x668db0af, 9069000}},        // Last Petersburg block
        {9069000, ForkId{0x879d6e30, 9200000}},        // First Istanbul block
        {9199999, ForkId{0x879d6e30, 9200000}},        // Last Istanbul block
        {9200000, ForkId{0xe029e991, 12244000}},       // First Muir Glacier block
        {12243999, ForkId{0xe029e991, 12244000}},      // Last Muir Glacier block
        {12244000, ForkId{0x0eb440f6, 12965000}},      // First Berlin block
        {12964999, ForkId{0x0eb440f6, 12965000}},      // Last Berlin block
        {12965000, ForkId{0xb715077d, 13773000}},      // First London block
        {13772999, ForkId{0xb715077d, 13773000}},      // Last London block
        {13773000, ForkId{0x20c327fc, 15050000}},      // First Arrow Glacier block
        {15049999, ForkId{0x20c327fc, 15050000}},      // Last Arrow Glacier block
        {15050000, ForkId{0xf0afd0e3, 1681338455}},    // First Gray Glacier block
        {17034869, ForkId{0xf0afd0e3, 1681338455}},    // Last Gray Glacier block
        {1681338455, ForkId{0xdce96c2d, 1710338135}},  // First Shanghai block
        {1710338123, ForkId{0xdce96c2d, 1710338135}},  // Last Shanghai block
        {1710338135, ForkId{0x9f3d2254, 0}},           // First Cancun block
        {1800000000, ForkId{0x9f3d2254, 0}},           // Future Cancun block
    };

    auto chain_config{kMainnetConfig};
    chain_config.genesis_hash.emplace(kMainnetGenesisHash);
    for (auto& example : examples) {
        CHECK(fork_id_at(example.head_block_num_or_time, chain_config) == example.fork_id);
    }
}

TEST_CASE("ForkId.forks.sepolia") {
    std::vector<ForksExampleSpec> examples = {
        {0, ForkId{0xfe3366e7, 1735371}},              // Unsynced, last Frontier, Homestead, Tangerine, Spurious, Byzantium, Constantinople, Petersburg, Istanbul, Berlin and first London block
        {1735370, ForkId{0xfe3366e7, 1735371}},        // Last pre-MergeNetsplit block
        {1735371, ForkId{0xb96cbd13, 1677557088}},     // First MergeNetsplit block
        {1735372, ForkId{0xb96cbd13, 1677557088}},     // Last MergeNetsplit block
        {1677557088, ForkId{0xf7f9bc08, 1706655072}},  // First Shanghai block
        {1706655060, ForkId{0xf7f9bc08, 1706655072}},  // Last Shanghai block
        {1706655072, ForkId{0x88cf81d9, 1741159776}},  // First Cancun block
        {1741159764, ForkId{0x88cf81d9, 1741159776}},  // Last Cancun block
        {1741159776, ForkId{0xed88b5fd, 0}},           // First Prague block
        {1800000000, ForkId{0xed88b5fd, 0}},           // Future Prague block

    };

    auto chain_config{kSepoliaConfig};
    chain_config.genesis_hash.emplace(kSepoliaGenesisHash);
    for (auto& example : examples) {
        CHECK(fork_id_at(example.head_block_num_or_time, chain_config) == example.fork_id);
    }
}

struct CompatibleForksExampleSpec {
    BlockNum head_block_num{0};
    ForkId fork_id;
    bool is_compatible{false};
};

TEST_CASE("ForkId.is_compatible_with") {
    std::vector<CompatibleForksExampleSpec> examples = {
        // Local is mainnet Petersburg, remote announces the same. No future fork is announced.
        {7987396, ForkId{0x668db0af, 0}, true},

        // Local is mainnet Petersburg, remote announces the same. Remote also announces a next fork
        // at block 0xffffffff, but that is uncertain.
        {7987396, ForkId{0x668db0af, std::numeric_limits<uint64_t>::max()}, true},

        // Local is mainnet currently in Byzantium only (so it's aware of Petersburg), remote announces
        // also Byzantium, but it's not yet aware of Petersburg (e.g. non updated node before the fork).
        // In this case we don't know if Petersburg passed yet or not.
        {7279999, ForkId{0xa00bc324, 0}, true},

        // Local is mainnet currently in Byzantium only (so it's aware of Petersburg), remote announces
        // also Byzantium, and it's also aware of Petersburg (e.g. updated node before the fork). We
        // don't know if Petersburg passed yet (will pass) or not.
        {7279999, ForkId{0xa00bc324, 7280000}, true},

        // Local is mainnet currently in Byzantium only (so it's aware of Petersburg), remote announces
        // also Byzantium, and it's also aware of some random fork (e.g. misconfigured Petersburg). As
        // neither forks passed at neither nodes, they may mismatch, but we still connect for now.
        {7279999, ForkId{0xa00bc324, std::numeric_limits<uint64_t>::max()}, true},

        // Local is mainnet Petersburg, remote announces Byzantium + knowledge about Petersburg. Remote
        // is simply out of sync, accept.
        {7987396, ForkId{0xa00bc324, 7280000}, true},

        // Local is mainnet Petersburg, remote announces Spurious + knowledge about Byzantium. Remote
        // is definitely out of sync. It may or may not need the Petersburg update, we don't know yet.
        {7987396, ForkId{0x3edd5b10, 4370000}, true},

        // Local is mainnet Byzantium, remote announces Petersburg. Local is out of sync, accept.
        {7279999, ForkId{0x668db0af, 0}, true},

        // Local is mainnet Spurious, remote announces Byzantium, but is not aware of Petersburg. Local
        // out of sync. Local also knows about a future fork, but that is uncertain yet.
        {4369999, ForkId{0xa00bc324, 0}, true},

        // Local is mainnet Petersburg. remote announces Byzantium but is not aware of further forks.
        // Remote needs software update.
        {7987396, ForkId{0xa00bc324, 0}, false},

        // Local is mainnet Petersburg, and isn't aware of more forks. Remote announces Petersburg +
        // 0xffffffff. Local needs software update, reject.
        {7987396, ForkId{0x5cddc0e1, 0}, false},

        // Local is mainnet Byzantium, and is aware of Petersburg. Remote announces Petersburg +
        // 0xffffffff. Local needs software update, reject.
        {7279999, ForkId{0x5cddc0e1, 0}, false},

        // Local is mainnet Petersburg, remote is Rinkeby Petersburg.
        {7987396, ForkId{0xafec6b27, 0}, false},

        // Local is mainnet Petersburg, far in the future. Remote announces Gopherium (non-existing fork)
        // at some future block 88888888, for itself, but past block for local. Local is incompatible.
        //
        // This case detects non-upgraded nodes with majority hash power (typical Ropsten mess).
        {88888888, ForkId{0x668db0af, 88888888}, false},

        // Local is mainnet Byzantium. Remote is also in Byzantium, but announces Gopherium (non-existing
        // fork) at block 7279999, before Petersburg. Local is incompatible.
        {7279999, ForkId{0xa00bc324, 7279999}, false},
    };

    auto chain_config{kMainnetConfig};
    chain_config.genesis_hash.emplace(kMainnetGenesisHash);

    ByteView genesis_hash{*chain_config.genesis_hash};
    const auto fork_numbers = chain_config.distinct_fork_block_nums();
    const auto fork_times = chain_config.distinct_fork_times();

    for (auto& example : examples) {
        bool is_compatible = example.fork_id.is_compatible_with(
            genesis_hash,
            fork_numbers,
            fork_times,
            example.head_block_num);
        CHECK(is_compatible == example.is_compatible);
    }
}

}  // namespace silkworm::sentry::eth
