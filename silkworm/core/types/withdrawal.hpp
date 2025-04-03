// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <evmc/evmc.hpp>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/rlp/decode.hpp>

namespace silkworm {

struct Withdrawal {
    uint64_t index{0};
    uint64_t validator_index{0};
    evmc::address address{};
    uint64_t amount{0};  // in GWei

    friend bool operator==(const Withdrawal&, const Withdrawal&) = default;
};

namespace rlp {
    size_t length(const Withdrawal&);
    void encode(Bytes& to, const Withdrawal&);
    DecodingResult decode(ByteView& from, Withdrawal& to, Leftover mode = Leftover::kProhibit) noexcept;
}  // namespace rlp

}  // namespace silkworm
