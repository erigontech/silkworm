// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "intra_block_state.hpp"

#include <bit>
#include <unordered_map>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/random_number.hpp>

#include "in_memory_state.hpp"

namespace silkworm {

static RandomNumber rnd_byte{0, UINT8_MAX};

static evmc::address random_address() {
    evmc::address a;
    for (uint8_t& byte : a.bytes) {
        byte = static_cast<uint8_t>(rnd_byte.generate_one());
    }
    return a;
}

static Bytes random_code() {
    static RandomNumber rnd_len{1, 60};
    const size_t len{static_cast<size_t>(rnd_len.generate_one())};
    Bytes code(len, 0);
    for (size_t i = 0; i < len; ++i) {
        code[i] = static_cast<uint8_t>(rnd_byte.generate_one());
    }
    return code;
}

// Check that insertion of new codes doesn't invalidate previously returned views of other codes.
TEST_CASE("Code view stability") {
    const size_t n{1000};

    // Generate preexisting codes
    InMemoryState db;
    std::vector<std::pair<evmc::address, Bytes>> existing_codes(n);
    for (size_t i = 0; i < n; ++i) {
        evmc::address addr{random_address()};
        Bytes code(random_code());
        existing_codes[i] = {addr, code};

        evmc_bytes32 code_hash{std::bit_cast<evmc_bytes32>(keccak256(code))};
        Account account{.code_hash = code_hash, .incarnation = kDefaultIncarnation};
        db.update_account(addr, /*initial=*/std::nullopt, /*current=*/account);
        db.update_account_code(addr, kDefaultIncarnation, code_hash, code);
    }

    IntraBlockState state{db};
    std::unordered_map<evmc::address, ByteView> code_views;
    std::vector<std::pair<evmc::address, Bytes>> new_codes;

    // Randomly get a view of an existing code from the state or insert a new code
    RandomNumber rnd{0, 2 * n - 1};
    for (size_t i = 0; i < n; ++i) {
        const auto x{static_cast<size_t>(rnd.generate_one())};
        if (x < n) {
            // Get a preexisting code
            evmc::address addr{existing_codes[x].first};
            code_views[addr] = state.get_code(addr);
        } else if (x < n + new_codes.size()) {
            // Get a newly inserted code
            evmc::address addr{new_codes[x - n].first};
            code_views[addr] = state.get_code(addr);
        } else {
            // Insert a new code
            evmc::address addr{random_address()};
            Bytes code(random_code());
            new_codes.emplace_back(addr, code);
            state.set_code(addr, code);
        }
    }

    // Check that all previously returned code views have correct code hashes
    for (const auto& cv : code_views) {
        evmc_bytes32 code_hash{std::bit_cast<evmc_bytes32>(keccak256(cv.second))};
        CHECK(state.get_code_hash(cv.first) == code_hash);
    }
}

}  // namespace silkworm
