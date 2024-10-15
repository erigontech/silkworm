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

#include <filesystem>
#include <optional>
#include <variant>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/sentry/common/ecc_key_pair.hpp>

namespace silkworm::sentry {

using NodeKey = EccKeyPair;

class NodeKeyConfig {
  public:
    explicit NodeKeyConfig(std::filesystem::path path);
    explicit NodeKeyConfig(const DataDirectory& data_dir);

    NodeKey load() const;

    void save(const NodeKey& key) const;

    bool exists() const;

  private:
    std::filesystem::path path_;
};

NodeKey node_key_get_or_generate(
    const std::optional<std::variant<std::filesystem::path, Bytes>>& node_key_option,
    const DataDirectory& data_dir);

}  // namespace silkworm::sentry
