// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <filesystem>
#include <memory>
#include <string_view>

#include <silkworm/core/common/base.hpp>

namespace silkworm::rpc {

class InterfaceLogImpl;

struct InterfaceLogSettings {
    bool enabled{false};
    std::string ifc_name;
    std::filesystem::path container_folder{"logs/"};
    size_t max_file_size_mb{1};
    size_t max_files{100};
    bool auto_flush{true};
    bool dump_response{false};
};

class InterfaceLog final {
  public:
    static const size_t kLogLineHeaderSize;

    explicit InterfaceLog(InterfaceLogSettings settings);
    ~InterfaceLog();

    // Not copyable
    InterfaceLog(const InterfaceLog&) = delete;
    InterfaceLog& operator=(const InterfaceLog&) = delete;

    // Only movable
    InterfaceLog(InterfaceLog&&) noexcept = default;
    InterfaceLog& operator=(InterfaceLog&&) noexcept = default;

    std::filesystem::path path() const;

    void log_req(std::string_view msg);
    void log_rsp(std::string_view msg);

    void flush();

  private:
    std::unique_ptr<InterfaceLogImpl> p_impl_;
};

}  // namespace silkworm::rpc
