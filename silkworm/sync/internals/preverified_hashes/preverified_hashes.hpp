// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <map>
#include <set>
#include <utility>

#include <evmc/evmc.hpp>

#include <silkworm/core/common/base.hpp>

namespace silkworm {

/*
 * PreverifiedHashes contains a set of headers that are known to belong to the canonical chain (i.e. they have been
 * added to the chain and the probability of them being removed is very close to zero).  Any header that is a parent of
 * a pre-verified header, can be considered to be pre-verified. This structure is used by the header downloader to skip
 * header verification for very old headers. Theoretically, it would be enough to only specify one pre-verified header.
 * But in practice, it makes sense to have a lot of them so that verification does not require loading the entire header
 * chain first.
 *
 * The set of pre-verified hashes must be generated with the toolbox utility provided with Silkworm and added manually
 * to the build of Silkworm. This is a task that will be accomplished by Silkworm authors that know which set of header
 * to add. The toolbox generate a .cpp file for a chain using headers in the chain local db. The generated file contains
 * the code that initialise a static instance of PreverifiedHashes so this instance must be listed here, as member of
 * the PreverifiedHashes class, like mainnet below. For the mainnet is already provided a file
 * preverified_hashes_mainnet.cpp
 *
 */

struct PreverifiedHashes {
    std::set<evmc::bytes32> hashes;  // Set of hashes of headers that are known to belong to canonical chain
    uint64_t block_num{0};           // Block block_num corresponding to the max pre-verified header
    uint64_t step{0};

    bool contains(const evmc::bytes32& hash) const;  // return true if hash is in the set of preverified hashes

    // global instance & method to init it
    static PreverifiedHashes& load(uint64_t chain_id);  // Load a set of pre-verified hashes from low level impl
};

}  // namespace silkworm
