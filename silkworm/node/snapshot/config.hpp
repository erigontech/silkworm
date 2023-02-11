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

#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <silkworm/core/common/base.hpp>

namespace silkworm::snapshot {

struct PreverifiedEntry {
    std::string file_name;
    std::string torrent_hash;
};

using PreverifiedList = std::vector<PreverifiedEntry>;

PreverifiedList from_toml(std::string_view preverified_toml_doc);

class Config {
  public:
    static std::shared_ptr<const Config> lookup_known_config(uint64_t chain_id, const std::vector<std::string>& whitelist);

    explicit Config(PreverifiedList preverified_snapshots);

    [[nodiscard]] const PreverifiedList& preverified_snapshots() const { return preverified_snapshots_; }
    [[nodiscard]] BlockNum max_block_number() const { return max_block_number_; }

  private:
    static const Config kGoerliSnapshotConfig;
    static const Config kMainnetSnapshotConfig;
    static const Config kSepoliaSnapshotConfig;

    static const std::map<uint64_t, const Config*> kKnownSnapshotConfigs;

    BlockNum compute_max_block();

    PreverifiedList preverified_snapshots_;
    BlockNum max_block_number_;
};

}  // namespace silkworm::snapshot
