// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
