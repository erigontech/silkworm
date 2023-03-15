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

#include "fork.hpp"

#include <keccak.h>

#include <silkworm/node/common/log.hpp>
#include <silkworm/lightclient/util/time.hpp>
#include <silkworm/lightclient/ssz/common/containers.hpp>

namespace silkworm::cl {

using namespace std::chrono;

static ForkVersion get_current_fork_version(uint64_t current_epoch, const BeaconChainConfig& bcc) {
    auto current_fork_version = bcc.genesis_fork_version;
    for (const auto& fork : bcc.sorted_fork_list()) {
        if (current_epoch < fork.epoch) {
            break;
        }
        current_fork_version = fork.version;
    }
    return current_fork_version;
}

Digest compute_fork_digest_for_version(ForkVersion fork_version, const Hash32& genesis_validators_root) {
    eth::ForkData fork_data;
    fork_data.current_version = eth::Version{fork_version};
    fork_data.genesis_validators_root = eth::Root{{reinterpret_cast<const char*>(genesis_validators_root.bytes), kHashLength}};
    log::Info() << "[Checkpoint Sync] fork_data hash tree root: " << to_hex(fork_data.hash_tree_root());

    Hash32 current_version;
    std::copy(fork_version.begin(), fork_version.end(), current_version.bytes);
    Keccak keccak256;
    keccak256.add(current_version.bytes, kHashLength);
    keccak256.add(genesis_validators_root.bytes, kHashLength);
    log::Info() << "[Checkpoint Sync] current_version: " << to_hex(current_version);
    log::Info() << "[Checkpoint Sync] genesis_validators_root: " << to_hex(genesis_validators_root);
    const auto data_root = keccak256.getHash();
    const auto root = from_hex(data_root);
    log::Info() << "[Checkpoint Sync] Fork data_root: " << data_root;

    Bytes input;
    input.reserve(2 * kHashLength);
    input.resize(2 * kHashLength);
    std::copy(current_version.bytes, current_version.bytes + kHashLength, input.begin());
    std::copy(genesis_validators_root.bytes, genesis_validators_root.bytes + kHashLength, input.begin() + kHashLength);
    log::Info() << "[Checkpoint Sync] input: " << to_hex(input);
    const auto hash = ethash::keccak256(input.data(), input.size());
    log::Info() << "[Checkpoint Sync] output: " << to_hex(hash.bytes);




    if (!root || root->size() != kHashLength) {
        throw std::runtime_error{"invalid keccak hash: " + data_root};
    }
    log::Info() << "[Checkpoint Sync] Fork root: " << to_hex(*root);
    Digest fork_digest{};
    std::copy(root->cbegin(), root->cbegin() + kDigestLength, fork_digest.begin());
    return fork_digest;
}

Digest compute_fork_digest(const BeaconChainConfig& bcc, const GenesisConfig& gc) {
    if (gc.genesis_time == 0) {
        throw std::runtime_error{"genesis time is not set"};
    }
    if (!gc.genesis_validator_root) {
        throw std::runtime_error{"genesis validator root is not set"};
    }
    const auto current_epoch = get_current_epoch(gc.genesis_time, bcc.seconds_per_slot, bcc.slots_per_epoch);
    const auto current_fork_version = get_current_fork_version(current_epoch, bcc);
    return compute_fork_digest_for_version(current_fork_version, gc.genesis_validator_root);
}

}  // namespace silkworm::cl
