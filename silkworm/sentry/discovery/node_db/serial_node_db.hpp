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

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>

#include "node_db.hpp"

namespace silkworm::sentry::discovery::node_db {

class SerialNodeDb : public NodeDb {
  public:
    SerialNodeDb(
        NodeDb& db,
        boost::asio::any_io_executor executor)
        : db_(db),
          strand_(boost::asio::make_strand(std::move(executor))) {}
    ~SerialNodeDb() override = default;

    Task<void> upsert_node_address(NodeId id, NodeAddress address) override;
    Task<std::optional<NodeAddress>> find_node_address_v4(NodeId id) override;
    Task<std::optional<NodeAddress>> find_node_address_v6(NodeId id) override;
    Task<void> update_last_ping_time(NodeId id, Time value) override;
    Task<std::optional<Time>> find_last_ping_time(NodeId id) override;
    Task<void> update_last_pong_time(NodeId id, Time value) override;
    Task<std::optional<Time>> find_last_pong_time(NodeId id) override;
    Task<void> delete_node(NodeId id) override;

  private:
    NodeDb& db_;
    boost::asio::strand<boost::asio::any_io_executor> strand_;
};

}  // namespace silkworm::sentry::discovery::node_db
