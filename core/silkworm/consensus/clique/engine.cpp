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

#include "engine.hpp"

#include <silkpre/ecdsa.h>

namespace silkworm::consensus {

ValidationResult CliqueEngine::validate_seal(const BlockHeader&) { return ValidationResult::kOk; }

evmc::address CliqueEngine::get_beneficiary(const BlockHeader& header) { 
      return ecrecover(header);
}

evmc::address 
CliqueEngine::ecrecover(const BlockHeader& header) {
    evmc::address beneficiary = evmc::address{};

    evmc::bytes32 seal_hash = header.hash(false, true);
    std::cout << "erecover: seal-hash: " << silkworm::to_hex(seal_hash.bytes) << "\n";
    Bytes signature = header.extra_data.substr(header.extra_data.length() - kEntraSealSize, kEntraSealSize - 1);
    std::cout << "erecover: signature: " << silkworm::to_hex(signature) << "\n";
    bool odd_y_parity = header.extra_data[header.extra_data.length() - 1] == 1;
    std::cout << "erecover: parity: " << odd_y_parity << "\n";

    static secp256k1_context* context{secp256k1_context_create(SILKPRE_SECP256K1_CONTEXT_FLAGS)};
    if (!silkpre_recover_address(beneficiary.bytes, seal_hash.bytes, signature.c_str(), odd_y_parity, context)) {
        return header.beneficiary;
    }
    std::cout << "erecover: beneficiary: " << silkworm::to_hex(beneficiary) << "\n";

    return beneficiary;
}

}  // namespace silkworm::consensus
