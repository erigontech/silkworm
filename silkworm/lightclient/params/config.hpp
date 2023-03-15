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
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/lightclient/util/hash32.hpp>

namespace silkworm::cl {

constexpr std::size_t kForkVersionLength{4};

using ChainId = uint64_t;
using ForkVersion = std::array<uint8_t, kForkVersionLength>;

//! Bootstrap nodes for Mainnet Beacon chain
const std::vector<std::string> kMainnetBootstrapNodes = {
    // Teku team's bootnodes
    "enr:-KG4QOtcP9X1FbIMOe17QNMKqDxCpm14jcX5tiOE4_TyMrFqbmhPZHK_ZPG2Gxb1GE2xdtodOfx9-cgvNtxnRyHEmC0ghGV0aDKQ9aX9QgAAAAD__________4JpZIJ2NIJpcIQDE8KdiXNlY3AyNTZrMaEDhpehBDbZjM_L9ek699Y7vhUJ-eAdMyQW_Fil522Y0fODdGNwgiMog3VkcIIjKA",
    "enr:-KG4QL-eqFoHy0cI31THvtZjpYUu_Jdw_MO7skQRJxY1g5HTN1A0epPCU6vi0gLGUgrzpU-ygeMSS8ewVxDpKfYmxMMGhGV0aDKQtTA_KgAAAAD__________4JpZIJ2NIJpcIQ2_DUbiXNlY3AyNTZrMaED8GJ2vzUqgL6-KD1xalo1CsmY4X1HaDnyl6Y_WayCo9GDdGNwgiMog3VkcIIjKA",
    // Prylab team's bootnodes
    "enr:-Ku4QImhMc1z8yCiNJ1TyUxdcfNucje3BGwEHzodEZUan8PherEo4sF7pPHPSIB1NNuSg5fZy7qFsjmUKs2ea1Whi0EBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQOVphkDqal4QzPMksc5wnpuC3gvSC8AfbFOnZY_On34wIN1ZHCCIyg",
    "enr:-Ku4QP2xDnEtUXIjzJ_DhlCRN9SN99RYQPJL92TMlSv7U5C1YnYLjwOQHgZIUXw6c-BvRg2Yc2QsZxxoS_pPRVe0yK8Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQMeFF5GrS7UZpAH2Ly84aLK-TyvH-dRo0JM1i8yygH50YN1ZHCCJxA",
    "enr:-Ku4QPp9z1W4tAO8Ber_NQierYaOStqhDqQdOPY3bB3jDgkjcbk6YrEnVYIiCBbTxuar3CzS528d2iE7TdJsrL-dEKoBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQMw5fqqkw2hHC4F5HZZDPsNmPdB1Gi8JPQK7pRc9XHh-oN1ZHCCKvg",
    // Lighthouse team's bootnodes
    "enr:-Jq4QItoFUuug_n_qbYbU0OY04-np2wT8rUCauOOXNi0H3BWbDj-zbfZb7otA7jZ6flbBpx1LNZK2TDebZ9dEKx84LYBhGV0aDKQtTA_KgEAAAD__________4JpZIJ2NIJpcISsaa0ZiXNlY3AyNTZrMaEDHAD2JKYevx89W0CcFJFiskdcEzkH_Wdv9iW42qLK79ODdWRwgiMo",
    "enr:-Jq4QN_YBsUOqQsty1OGvYv48PMaiEt1AzGD1NkYQHaxZoTyVGqMYXg0K9c0LPNWC9pkXmggApp8nygYLsQwScwAgfgBhGV0aDKQtTA_KgEAAAD__________4JpZIJ2NIJpcISLosQxiXNlY3AyNTZrMaEDBJj7_dLFACaxBfaI8KZTh_SSJUjhyAyfshimvSqo22WDdWRwgiMo",
    // EF bootnodes
    "enr:-Ku4QHqVeJ8PPICcWk1vSn_XcSkjOkNiTg6Fmii5j6vUQgvzMc9L1goFnLKgXqBJspJjIsB91LTOleFmyWWrFVATGngBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhAMRHkWJc2VjcDI1NmsxoQKLVXFOhp2uX6jeT0DvvDpPcU8FWMjQdR4wMuORMhpX24N1ZHCCIyg",
    "enr:-Ku4QG-2_Md3sZIAUebGYT6g0SMskIml77l6yR-M_JXc-UdNHCmHQeOiMLbylPejyJsdAPsTHJyjJB2sYGDLe0dn8uYBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhBLY-NyJc2VjcDI1NmsxoQORcM6e19T1T9gi7jxEZjk_sjVLGFscUNqAY9obgZaxbIN1ZHCCIyg",
    "enr:-Ku4QPn5eVhcoF1opaFEvg1b6JNFD2rqVkHQ8HApOKK61OIcIXD127bKWgAtbwI7pnxx6cDyk_nI88TrZKQaGMZj0q0Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhDayLMaJc2VjcDI1NmsxoQK2sBOLGcUb4AwuYzFuAVCaNHA-dy24UuEKkeFNgCVCsIN1ZHCCIyg",
    "enr:-Ku4QEWzdnVtXc2Q0ZVigfCGggOVB2Vc1ZCPEc6j21NIFLODSJbvNaef1g4PxhPwl_3kax86YPheFUSLXPRs98vvYsoBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhDZBrP2Jc2VjcDI1NmsxoQM6jr8Rb1ktLEsVcKAPa08wCsKUmvoQ8khiOl_SLozf9IN1ZHCCIyg",
    // Nimbus bootnodes
    "enr:-LK4QA8FfhaAjlb_BXsXxSfiysR7R52Nhi9JBt4F8SPssu8hdE1BXQQEtVDC3qStCW60LSO7hEsVHv5zm8_6Vnjhcn0Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhAN4aBKJc2VjcDI1NmsxoQJerDhsJ-KxZ8sHySMOCmTO6sHM3iCFQ6VMvLTe948MyYN0Y3CCI4yDdWRwgiOM",
    "enr:-LK4QKWrXTpV9T78hNG6s8AM6IO4XH9kFT91uZtFg1GcsJ6dKovDOr1jtAAFPnS2lvNltkOGA9k29BUN7lFh_sjuc9QBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhANAdd-Jc2VjcDI1NmsxoQLQa6ai7y9PMN5hpLe5HmiJSlYzMuzP7ZhwRiwHvqNXdoN0Y3CCI4yDdWRwgiOM",
};

//! Bootstrap nodes for Goerli Beacon chain
const std::vector<std::string> kGoerliBootstrapNodes = {
    "enr:-Ku4QFmUkNp0g9bsLX2PfVeIyT-9WO-PZlrqZBNtEyofOOfLMScDjaTzGxIb1Ns9Wo5Pm_8nlq-SZwcQfTH2cgO-s88Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpDkvpOTAAAQIP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQLV_jMOIxKbjHFKgrkFvwDvpexo6Nd58TK5k7ss4Vt0IoN1ZHCCG1g",
    "enr:-LK4QH1xnjotgXwg25IDPjrqRGFnH1ScgNHA3dv1Z8xHCp4uP3N3Jjl_aYv_WIxQRdwZvSukzbwspXZ7JjpldyeVDzMCh2F0dG5ldHOIAAAAAAAAAACEZXRoMpB53wQoAAAQIP__________gmlkgnY0gmlwhIe1te-Jc2VjcDI1NmsxoQOkcGXqbCJYbcClZ3z5f6NWhX_1YPFRYRRWQpJjwSHpVIN0Y3CCIyiDdWRwgiMo",
    "enr:-Ly4QFPk-cTMxZ3jWTafiNblEZkQIXGF2aVzCIGW0uHp6KaEAvBMoctE8S7YU0qZtuS7By0AA4YMfKoN9ls_GJRccVpFh2F0dG5ldHOI__________-EZXRoMpCC9KcrAgAQIIS2AQAAAAAAgmlkgnY0gmlwhKh3joWJc2VjcDI1NmsxoQKrxz8M1IHwJqRIpDqdVW_U1PeixMW5SfnBD-8idYIQrIhzeW5jbmV0cw-DdGNwgiMog3VkcIIjKA",
    "enr:-L64QJmwSDtaHVgGiqIxJWUtxWg6uLCipsms6j-8BdsOJfTWAs7CLF9HJnVqFE728O-JYUDCxzKvRdeMqBSauHVCMdaCAVWHYXR0bmV0c4j__________4RldGgykIL0pysCABAghLYBAAAAAACCaWSCdjSCaXCEQWxOdolzZWNwMjU2azGhA7Qmod9fK86WidPOzLsn5_8QyzL7ZcJ1Reca7RnD54vuiHN5bmNuZXRzD4N0Y3CCIyiDdWRwgiMo",
    "enr:-KG4QCIzJZTY_fs_2vqWEatJL9RrtnPwDCv-jRBuO5FQ2qBrfJubWOWazri6s9HsyZdu-fRUfEzkebhf1nvO42_FVzwDhGV0aDKQed8EKAAAECD__________4JpZIJ2NIJpcISHtbYziXNlY3AyNTZrMaED4m9AqVs6F32rSCGsjtYcsyfQE2K8nDiGmocUY_iq-TSDdGNwgiMog3VkcIIjKA",
};

//! Bootstrap nodes for Sepolia Beacon chain
const std::vector<std::string> kSepoliaBootstrapNodes = {
    // EF boot nodes
    "enr:-Iq4QMCTfIMXnow27baRUb35Q8iiFHSIDBJh6hQM5Axohhf4b6Kr_cOCu0htQ5WvVqKvFgY28893DHAg8gnBAXsAVqmGAX53x8JggmlkgnY0gmlwhLKAlv6Jc2VjcDI1NmsxoQK6S-Cii_KmfFdUJL2TANL3ksaKUnNXvTCv1tLwXs0QgIN1ZHCCIyk",
    "enr:-KG4QE5OIg5ThTjkzrlVF32WT_-XT14WeJtIz2zoTqLLjQhYAmJlnk4ItSoH41_2x0RX0wTFIe5GgjRzU2u7Q1fN4vADhGV0aDKQqP7o7pAAAHAyAAAAAAAAAIJpZIJ2NIJpcISlFsStiXNlY3AyNTZrMaEC-Rrd_bBZwhKpXzFCrStKp1q_HmGOewxY3KwM8ofAj_ODdGNwgiMog3VkcIIjKA",
    // Teku boot node
    "enr:-Ly4QFoZTWR8ulxGVsWydTNGdwEESueIdj-wB6UmmjUcm-AOPxnQi7wprzwcdo7-1jBW_JxELlUKJdJES8TDsbl1EdNlh2F0dG5ldHOI__78_v2bsV-EZXRoMpA2-lATkAAAcf__________gmlkgnY0gmlwhBLYJjGJc2VjcDI1NmsxoQI0gujXac9rMAb48NtMqtSTyHIeNYlpjkbYpWJw46PmYYhzeW5jbmV0cw-DdGNwgiMog3VkcIIjKA",
};

//! Trusted checkpoint sync endpoints: https://eth-clients.github.io/checkpoint-sync-endpoints/
const std::map<ChainId, std::vector<std::string>> kCheckpointSyncEndpoints = {
    {kMainnetConfig.chain_id,
     {
         "https://beaconstate.ethstaker.cc/eth/v2/debug/beacon/states/finalized",
         "https://sync.invis.tools/eth/v2/debug/beacon/states/finalized",
         "https://mainnet-checkpoint-sync.attestant.io/eth/v2/debug/beacon/states/finalized",
         "https://mainnet.checkpoint.sigp.io/eth/v2/debug/beacon/states/finalized",
         "https://mainnet-checkpoint-sync.stakely.io/eth/v2/debug/beacon/states/finalized",
         "https://checkpointz.pietjepuk.net/eth/v2/debug/beacon/states/finalized",
     }},
    {kGoerliConfig.chain_id,
     {
         "https://goerli.beaconstate.info/eth/v2/debug/beacon/states/finalized",
         "https://goerli.beaconstate.ethstaker.cc/eth/v2/debug/beacon/states/finalized",
         "https://goerli-sync.invis.tools/eth/v2/debug/beacon/states/finalized",
         "https://goerli.checkpoint-sync.ethdevops.io/eth/v2/debug/beacon/states/finalized",
         "https://prater-checkpoint-sync.stakely.io/eth/v2/debug/beacon/states/finalized",
     }},
    {kSepoliaConfig.chain_id,
     {
         "https://sepolia.checkpoint-sync.ethdevops.io/eth/v2/debug/beacon/states/finalized",
         "https://sepolia.beaconstate.info/eth/v2/debug/beacon/states/finalized",
     }},
};

//! \brief Lookup a known checkpoint sync endpoint provided its chain ID
std::optional<std::string> get_checkpoint_sync_endpoint(ChainId chain_id) noexcept;

struct Fork {
    uint64_t epoch;
    ForkVersion version;
};

//! Configuration parameters for node to participate in beacon chain
struct BeaconChainConfig {
    uint64_t genesis_slot{0};   // The first canonical slot number of the beacon chain
    uint64_t genesis_epoch{0};  // The first canonical epoch number of the beacon chain

    // Time parameters constants
    uint64_t seconds_per_slot{0};  // How many seconds are in a single slot
    uint64_t slots_per_epoch{0};   // The number of slots in one epoch

    // Fork-related values
    ForkVersion genesis_fork_version;    // Used to track fork version between state transitions
    ForkVersion altair_fork_version;     // Used to represent the fork version for Altair
    uint64_t altair_fork_epoch{0};       // Used to represent the assigned fork epoch for Altair
    ForkVersion bellatrix_fork_version;  // Used to represent the fork version for Bellatrix
    uint64_t bellatrix_fork_epoch{0};    // Used to represent the assigned fork epoch for Bellatrix
    ForkVersion capella_fork_version;    // Used to represent the fork version for Capella
    uint64_t capella_fork_epoch{0};      // Used to represent the assigned fork epoch for Capella
    ForkVersion sharding_fork_version;   // Used to represent the fork version for sharding
    uint64_t sharding_fork_epoch{0};     // Used to represent the assigned fork epoch for sharding

    [[nodiscard]] std::vector<Fork> sorted_fork_list() const;
};

inline constexpr BeaconChainConfig kMainnetBeaconConfig{
    // Time parameters constants
    .seconds_per_slot = 12,
    .slots_per_epoch = 32,

    // Fork-related values
    .genesis_fork_version = {0x00, 0x00, 0x00, 0x00},
    .altair_fork_version = {0x01, 0x00, 0x00, 0x00},
    .altair_fork_epoch = 74240,
    .bellatrix_fork_version = {0x02, 0x00, 0x00, 0x00},
    .bellatrix_fork_epoch = 144869,
    .capella_fork_version = {0x03, 0x00, 0x00, 0x00},
    .capella_fork_epoch = std::numeric_limits<uint64_t>::max(),
    .sharding_fork_version = {0x04, 0x00, 0x00, 0x00},
    .sharding_fork_epoch = std::numeric_limits<uint64_t>::max(),
};

inline constexpr BeaconChainConfig kSepoliaBeaconConfig{
    // Time parameters constants
    .seconds_per_slot = 12,
    .slots_per_epoch = 32,

    // Fork-related values
    .genesis_fork_version = {0x90, 0x00, 0x00, 0x69},
    .altair_fork_version = {0x90, 0x00, 0x00, 0x70},
    .altair_fork_epoch = 50,
    .bellatrix_fork_version = {0x90, 0x00, 0x00, 0x71},
    .bellatrix_fork_epoch = 100,
    .capella_fork_version = {0x90, 0x00, 0x00, 0x72},
    .capella_fork_epoch = std::numeric_limits<uint64_t>::max(),
    .sharding_fork_version = {0x90, 0x00, 0x00, 0x73},
    .sharding_fork_epoch = std::numeric_limits<uint64_t>::max(),
};

inline constexpr BeaconChainConfig kGoerliBeaconConfig{
    // Time parameters constants
    .seconds_per_slot = 12,
    .slots_per_epoch = 32,

    // Fork-related values
    .genesis_fork_version = {0x00, 0x00, 0x10, 0x20},
    .altair_fork_version = {0x01, 0x00, 0x10, 0x20},
    .altair_fork_epoch = 36660,
    .bellatrix_fork_version = {0x02, 0x00, 0x10, 0x20},
    .bellatrix_fork_epoch = 112260,
    .capella_fork_version = {0x03, 0x00, 0x10, 0x20},
    .capella_fork_epoch = std::numeric_limits<uint64_t>::max(),
    .sharding_fork_version = {0x04, 0x00, 0x10, 0x20},
    .sharding_fork_epoch = std::numeric_limits<uint64_t>::max(),
};

//! Configuration parameters for node static genesis
struct GenesisConfig {
    Hash32 genesis_validator_root;  // Merkle root at genesis
    uint64_t genesis_time{0};       // Unix time epoch at genesis
};

inline constexpr GenesisConfig kMainnetGenesisConfig{
    .genesis_validator_root = 0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95_bytes32,
    .genesis_time = 1606824023
};

inline constexpr GenesisConfig kSepoliaGenesisConfig{
    .genesis_validator_root = 0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078_bytes32,
    .genesis_time = 1655733600
};

inline constexpr GenesisConfig kGoerliGenesisConfig{
    .genesis_validator_root = 0x043db0d9a83813551ee2f33450d23797757d430911a9320530ad8a0eabc43efb_bytes32,
    .genesis_time = 1616508000
};

//! Configuration parameters for node peer-to-peer networking
struct NetworkConfig {
};

inline constexpr NetworkConfig kMainnetNetworkConfig{
};

inline constexpr NetworkConfig kSepoliaNetworkConfig{
};

inline constexpr NetworkConfig kGoerliNetworkConfig{
};

struct ConsensusConfig {
    GenesisConfig genesis_config;
    BeaconChainConfig beacon_chain_config;
    NetworkConfig network_config;
};

inline constexpr ConsensusConfig kMainnetConsensusConfig{
    .genesis_config = kMainnetGenesisConfig,
    .beacon_chain_config = kMainnetBeaconConfig,
    .network_config = kMainnetNetworkConfig,
};

inline constexpr ConsensusConfig kSepoliaConsensusConfig{
    .genesis_config = kSepoliaGenesisConfig,
    .beacon_chain_config = kSepoliaBeaconConfig,
    .network_config = kSepoliaNetworkConfig,
};

inline constexpr ConsensusConfig kGoerliConsensusConfig{
    .genesis_config = kGoerliGenesisConfig,
    .beacon_chain_config = kGoerliBeaconConfig,
    .network_config = kGoerliNetworkConfig,
};

//! \brief Lookup a known consensus config provided the chain identifier
const ConsensusConfig* lookup_consensus_config(ChainId chain_id) noexcept;

}  // namespace silkworm::cl
