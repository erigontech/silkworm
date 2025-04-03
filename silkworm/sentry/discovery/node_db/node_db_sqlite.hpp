// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <filesystem>
#include <memory>

#include <boost/asio/any_io_executor.hpp>

#include "node_db.hpp"

namespace silkworm::sentry::discovery::node_db {

class NodeDbSqliteImpl;

class NodeDbSqlite {
  public:
    explicit NodeDbSqlite(const boost::asio::any_io_executor& executor);
    ~NodeDbSqlite();

    void setup(const std::filesystem::path& db_dir_path);
    void setup_in_memory();

    NodeDb& interface();

  private:
    std::unique_ptr<NodeDbSqliteImpl> p_impl_;
    std::unique_ptr<NodeDb> interface_;
};

}  // namespace silkworm::sentry::discovery::node_db
