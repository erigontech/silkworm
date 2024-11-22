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

#include <ostream>
#include <string>
#include <string_view>

#include <evmc/evmc.hpp>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/rlp/decode.hpp>

#include "silkworm/core/common/decoding_result.hpp"

namespace silkworm {

// Yellow Paper, Section 7
evmc::address create_address(const evmc::address& caller, uint64_t nonce) noexcept;

// https://eips.ethereum.org/EIPS/eip-1014
evmc::address create2_address(const evmc::address& caller, const evmc::bytes32& salt,
                              uint8_t (&code_hash)[32]) noexcept;

// Converts bytes to evmc::address; input is cropped if necessary.
// Short inputs are left-padded with 0s.
evmc::address bytes_to_address(ByteView bytes);

// Similar to HexToAddress in erigon-lib.
// Terminates the program if hex is not a valid hex encoding, unless return_zero_on_err is true.
evmc::address hex_to_address(std::string_view hex, bool return_zero_on_err = false);

std::string address_to_hex(const evmc::address& address);

namespace rlp {
    void encode(Bytes& to, const evmc::address& address);
    DecodingResult decode(ByteView& from, evmc::address& address, Leftover mode = Leftover::kProhibit);
    size_t length(const evmc::address& address) noexcept;
}  // namespace rlp

}  // namespace silkworm

namespace evmc {

std::ostream& operator<<(std::ostream& out, const evmc::address& address);

}  // namespace evmc
