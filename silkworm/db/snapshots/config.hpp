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

#include <vector>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/base.hpp>

#include "entry.hpp"

namespace silkworm::snapshots {

using PreverifiedList = std::vector<Entry>;

class Config {
  public:
    static Config lookup_known_config(ChainId chain_id);

    explicit Config(PreverifiedList entries);

    [[nodiscard]] const PreverifiedList& preverified_snapshots() const { return entries_; }
    [[nodiscard]] BlockNum max_block_number() const { return max_block_number_; }

  private:
    static BlockNum compute_max_block(const PreverifiedList& entries);
    static PreverifiedList remove_unsupported_snapshots(const PreverifiedList& entries);

    PreverifiedList entries_;
    BlockNum max_block_number_;
};

}  // namespace silkworm::snapshots
