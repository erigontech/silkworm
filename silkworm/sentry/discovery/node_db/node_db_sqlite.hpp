/*
   Copyright 2023 The Silkworm Authors

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
