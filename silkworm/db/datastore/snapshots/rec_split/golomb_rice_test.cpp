// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "golomb_rice.hpp"

#include <cstdint>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/random_number.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::snapshots::rec_split {

using silkworm::snapshots::encoding::Uint32Sequence;
using silkworm::snapshots::encoding::Uint64Sequence;

static constexpr size_t kGolombRiceTestNumKeys{128};
static constexpr size_t kGolombRiceTestNumTrees{1'000};

static Uint64Sequence generate_keys() {
    static RandomNumber rnd(32, 64);

    Uint64Sequence keys;
    for (size_t i = 0; i < kGolombRiceTestNumKeys; ++i) {
        keys.push_back(rnd.generate_one());
    }

    return keys;
}

static GolombRiceVector build_vector(const Uint64Sequence& keys, uint64_t golomb_param) {
    GolombRiceVector::Builder builder;

    for (size_t t{0}; t < kGolombRiceTestNumTrees; ++t) {
        Uint32Sequence unary;
        for (uint64_t k : keys) {
            builder.append_fixed(k, golomb_param);
            unary.push_back(static_cast<uint32_t>(k >> golomb_param));
        }
        builder.append_unary_all(unary);
    }

    return builder.build();
}

static void test_trees(GolombRiceVector& v, const Uint64Sequence& keys, uint64_t golomb_param, size_t tree_offset) {
    GolombRiceVector::Reader r = v.reader();

    for (size_t t{0}; t < kGolombRiceTestNumTrees; ++t) {
        r.read_reset(t * tree_offset, golomb_param * keys.size());
        for (uint64_t expected_key : keys) {
            uint64_t k = r.read_next(golomb_param);
            CHECK(k == expected_key);
        }
    }
}

TEST_CASE("GolombRiceVector", "[silkworm][recsplit][golomb_rice]") {
    const std::vector<size_t> golomb_params{0, 1, 2, 3, 4, 5, 6};
    for (size_t i{0}; i < golomb_params.size(); ++i) {
        SECTION("trees " + std::to_string(i)) {
            const uint64_t golomb_param = golomb_params[i];

            Uint64Sequence keys = generate_keys();
            GolombRiceVector v = build_vector(keys, golomb_param);
            size_t tree_offset{0};
            for (uint64_t k : keys) {
                tree_offset += 1 + (k >> golomb_param) + golomb_param;
            }
            test_trees(v, keys, golomb_param, tree_offset);
        }
    }
}

}  // namespace silkworm::snapshots::rec_split
