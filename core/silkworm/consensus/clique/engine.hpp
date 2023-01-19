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

#include <silkworm/consensus/ethash/engine.hpp>

namespace silkworm::consensus {

// This consensus engine does not validate PoW seal.
// It is used in the consensus tests.
class CliqueEngine : public EthashEngine {
  public:
    explicit CliqueEngine(const ChainConfig& chain_config) : EthashEngine(chain_config) {}

    //! \brief Validates the seal of the header
    ValidationResult validate_seal(const BlockHeader& header) final;

    evmc::address get_beneficiary(const BlockHeader& header) final;

  private:
    evmc::address ecrecover(const BlockHeader& header);
};

}  // namespace silkworm::consensus
