// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <filesystem>

namespace silkworm::snapshots {

class IndexSaltFile {
  public:
    explicit IndexSaltFile(std::filesystem::path path) : path_{std::move(path)} {}

    uint32_t load() const;
    void save(uint32_t value) const;
    bool exists() const { return std::filesystem::exists(path_); }

  private:
    std::filesystem::path path_;
};

}  // namespace silkworm::snapshots
