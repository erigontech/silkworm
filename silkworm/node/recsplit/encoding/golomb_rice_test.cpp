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

#include "golomb_rice.hpp"

#include <cstdint>
#include <random>

#include <catch2/catch.hpp>

#include <silkworm/infra/test/log.hpp>
#include <silkworm/node/recsplit/encoding/sequence.hpp>

namespace silkworm::succinct {

static const std::size_t kGolombRiceTestNumKeys{128};
static const std::size_t kGolombRiceTestNumTrees{1'000};

static Uint64Sequence generate_keys() {
    static std::random_device rd;
    static std::mt19937_64 rng(rd());
    static std::uniform_int_distribution<uint64_t> gen(32, 64);

    Uint64Sequence keys;
    for (std::size_t i = 0; i < kGolombRiceTestNumKeys; ++i) {
        keys.push_back(gen(rng));
    }

    return keys;
}

static GolombRiceVector build_vector(const Uint64Sequence& keys, uint64_t golomb_param) {
    GolombRiceVector::Builder builder;

    for (std::size_t t{0}; t < kGolombRiceTestNumTrees; ++t) {
        Uint32Sequence unary;
        for (uint64_t k : keys) {
            builder.append_fixed(k, golomb_param);
            unary.push_back(static_cast<uint32_t>(k >> golomb_param));
        }
        builder.append_unary_all(unary);
    }

    return builder.build();
}

static void test_trees(GolombRiceVector& v, const Uint64Sequence& keys, uint64_t golomb_param, std::size_t tree_offset) {
    GolombRiceVector::Reader r = v.reader();

    for (std::size_t t{0}; t < kGolombRiceTestNumTrees; ++t) {
        r.read_reset(t * tree_offset, golomb_param * keys.size());
        for (uint64_t expected_key : keys) {
            uint64_t k = r.read_next(golomb_param);
            CHECK(k == expected_key);
        }
    }
}

TEST_CASE("GolombRiceVector", "[silkworm][recsplit][golomb_rice]") {
    test::SetLogVerbosityGuard guard{log::Level::kNone};

    const std::vector<std::size_t> golomb_params{0, 1, 2, 3, 4, 5, 6};
    for (std::size_t i{0}; i < golomb_params.size(); ++i) {
        SECTION("trees " + std::to_string(i)) {
            const uint64_t golomb_param = golomb_params[i];

            Uint64Sequence keys = generate_keys();
            GolombRiceVector v = build_vector(keys, golomb_param);
            std::size_t tree_offset{0};
            for (uint64_t k : keys) {
                tree_offset += 1 + (k >> golomb_param) + golomb_param;
            }
            test_trees(v, keys, golomb_param, tree_offset);
        }
    }
}

}  // namespace silkworm::succinct
