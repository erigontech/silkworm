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

// See Yellow Paper, Appendix F "Signing Transactions"
// and EIP-155: Simple replay attack protection.

#include <optional>

#include <intx/intx.hpp>

namespace silkworm {

struct YParityAndChainId {
    bool odd{false};
    std::optional<intx::uint256> chain_id{std::nullopt};  // EIP-155
};

//! \brief Calculates Y parity from signature's V.
//! \param [in] v : signature V
//! \return Y parity and eventually chain Id
//! \remarks chain_id is always returned unless v ∈ {27, 28}
//! \see https://eips.ethereum.org/EIPS/eip-155.
std::optional<YParityAndChainId> v_to_y_parity_and_chain_id(const intx::uint256& v) noexcept;

//! \see https://eips.ethereum.org/EIPS/eip-155
intx::uint256 y_parity_and_chain_id_to_v(bool odd, const std::optional<intx::uint256>& chain_id) noexcept;

}  // namespace silkworm
