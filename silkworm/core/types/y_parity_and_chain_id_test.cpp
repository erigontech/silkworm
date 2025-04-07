// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "y_parity_and_chain_id.hpp"

#include <catch2/catch_test_macros.hpp>

namespace silkworm {

TEST_CASE("EIP-155 v to y parity & chain id ") {
    CHECK(v_to_y_parity_and_chain_id(0) == std::nullopt);
    CHECK(v_to_y_parity_and_chain_id(1) == std::nullopt);
    CHECK(v_to_y_parity_and_chain_id(25) == std::nullopt);
    CHECK(v_to_y_parity_and_chain_id(26) == std::nullopt);

    CHECK(v_to_y_parity_and_chain_id(27)->odd == false);
    CHECK(v_to_y_parity_and_chain_id(27)->chain_id == std::nullopt);
    CHECK(v_to_y_parity_and_chain_id(28)->odd == true);
    CHECK(v_to_y_parity_and_chain_id(28)->chain_id == std::nullopt);

    CHECK(v_to_y_parity_and_chain_id(29) == std::nullopt);
    CHECK(v_to_y_parity_and_chain_id(30) == std::nullopt);
    CHECK(v_to_y_parity_and_chain_id(31) == std::nullopt);
    CHECK(v_to_y_parity_and_chain_id(32) == std::nullopt);
    CHECK(v_to_y_parity_and_chain_id(33) == std::nullopt);
    CHECK(v_to_y_parity_and_chain_id(34) == std::nullopt);

    CHECK(v_to_y_parity_and_chain_id(35)->odd == false);
    CHECK(v_to_y_parity_and_chain_id(35)->chain_id == 0);
    CHECK(v_to_y_parity_and_chain_id(36)->odd == true);
    CHECK(v_to_y_parity_and_chain_id(36)->chain_id == 0);

    CHECK(v_to_y_parity_and_chain_id(37)->odd == false);
    CHECK(v_to_y_parity_and_chain_id(37)->chain_id == 1);
    CHECK(v_to_y_parity_and_chain_id(38)->odd == true);
    CHECK(v_to_y_parity_and_chain_id(38)->chain_id == 1);

    CHECK(y_parity_and_chain_id_to_v(false, std::nullopt) == 27);
    CHECK(y_parity_and_chain_id_to_v(true, std::nullopt) == 28);
    CHECK(y_parity_and_chain_id_to_v(false, 1) == 37);
    CHECK(y_parity_and_chain_id_to_v(true, 1) == 38);
}

}  // namespace silkworm
