// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <functional>
#include <optional>
#include <utility>
#include <vector>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/base.hpp>

#include "entry.hpp"

namespace silkworm::snapshots {

using PreverifiedList = std::vector<Entry>;
using PreverifiedListOfPairs = std::vector<std::pair<std::string_view, std::string_view>>;

class Config {
  public:
    static Config lookup_known_config(
        ChainId chain_id,
        std::optional<std::function<bool(std::string_view file_name)>> include_filter_opt = std::nullopt);

    explicit Config(PreverifiedList entries)
        : entries_(std::move(entries)) {}

    const PreverifiedList& preverified_snapshots() const { return entries_; }
    PreverifiedListOfPairs preverified_snapshots_as_pairs() const;
    bool contains_file_name(std::string_view file_name) const;

  private:
    static PreverifiedList remove_unsupported_entries(const PreverifiedList& entries);

    PreverifiedList entries_;
};

}  // namespace silkworm::snapshots
