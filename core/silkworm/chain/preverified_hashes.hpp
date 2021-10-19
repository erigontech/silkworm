/*
Copyright 2021 The Silkworm Authors

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

#ifndef SILKWORM_PREVERIFIED_HASHES_HPP
#define SILKWORM_PREVERIFIED_HASHES_HPP

#include <silkworm/common/base.hpp>
#include <silkworm/chain/identity.hpp>

#include <map>
#include <set>

namespace silkworm {

struct PreverifiedHashes {
    std::set<evmc::bytes32> hashes;
    uint64_t height{0};

    bool contains(const evmc::bytes32& hash) const { return hashes.find(hash) != hashes.end(); }

    static PreverifiedHashes none;
    static PreverifiedHashes mainnet;

    static std::map<uint64_t, const PreverifiedHashes&> per_chain;
};

inline PreverifiedHashes PreverifiedHashes::none = {{}, 0};

inline std::map<uint64_t, const PreverifiedHashes&> PreverifiedHashes::per_chain = { {0, none}, {1, mainnet} };

}

#endif  // SILKWORM_PREVERIFIED_HASHES_HPP
