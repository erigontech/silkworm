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

#include "node_db_sqlite.hpp"

#include <cassert>
#include <stdexcept>
#include <string>

#include <SQLiteCpp/SQLiteCpp.h>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/common/unix_timestamp.hpp>

#include "serial_node_db.hpp"

namespace silkworm::sentry::discovery::node_db {

static const char* kSqlCreateSchema = R"sql(

PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS nodes (
    id TEXT PRIMARY KEY,

    ip TEXT,
    port_disc INTEGER,
    port_rlpx INTEGER,
    ip_v6 TEXT,
    ip_v6_port_disc INTEGER,
    ip_v6_port_rlpx INTEGER,

    last_ping_time INTEGER,
    last_pong_time INTEGER,

    distance INTEGER NON NULL DEFAULT 256
);

CREATE INDEX IF NOT EXISTS idx_nodes_ip ON nodes (ip);
CREATE INDEX IF NOT EXISTS idx_nodes_ip_v6 ON nodes (ip_v6);
CREATE INDEX IF NOT EXISTS idx_last_ping_time ON nodes (last_ping_time);
CREATE INDEX IF NOT EXISTS idx_last_pong_time ON nodes (last_pong_time);
CREATE INDEX IF NOT EXISTS idx_distance ON nodes (distance);

)sql";

class NodeDbSqliteImpl : public NodeDb {
  public:
    NodeDbSqliteImpl() = default;
    ~NodeDbSqliteImpl() override = default;

    void setup(const std::filesystem::path& db_dir_path) {
        db_ = std::make_unique<SQLite::Database>(
            db_dir_path / "nodes.sqlite",
            SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE);
        db_->exec(kSqlCreateSchema);
    }

    void setup_in_memory() {
        db_ = std::make_unique<SQLite::Database>(
            ":memory:",
            SQLite::OPEN_READWRITE | SQLite::OPEN_MEMORY);
        db_->exec(kSqlCreateSchema);
    }

    Task<void> upsert_node_address(NodeId id, NodeAddress address) override {
        static const char* sql_ip_v4 = R"sql(
            INSERT INTO nodes(
                id,
                ip,
                port_disc,
                port_rlpx
            ) VALUES (?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                ip = excluded.ip,
                port_disc = excluded.port_disc,
                port_rlpx = excluded.port_rlpx
        )sql";

        static const char* sql_ip_v6 = R"sql(
            INSERT INTO nodes(
                id,
                ip_v6,
                ip_v6_port_disc,
                ip_v6_port_rlpx
            ) VALUES (?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                ip_v6 = excluded.ip_v6,
                ip_v6_port_disc = excluded.ip_v6_port_disc,
                ip_v6_port_rlpx = excluded.ip_v6_port_rlpx
        )sql";

        const char* sql = nullptr;
        if (address.ip.is_v4()) {
            sql = sql_ip_v4;
        }
        if (address.ip.is_v6()) {
            sql = sql_ip_v6;
        }
        assert(sql);
        if (!sql) {
            throw std::runtime_error("NodeDbSqliteImpl.upsert_node_address: unexpected ip type");
        }

        SQLite::Statement statement{*db_, sql};
        statement.bind(1, id.hex());
        statement.bind(2, address.ip.to_string());
        if (address.port_disc > 0)
            statement.bind(3, address.port_disc);
        if (address.port_rlpx > 0)
            statement.bind(4, address.port_rlpx);

        statement.exec();
        co_return;
    }

    Task<std::optional<NodeAddress>> find_node_address(NodeId id, const char* sql) {
        SQLite::Statement query{*db_, sql};
        query.bind(1, id.hex());

        if (!query.executeStep()) {
            co_return std::nullopt;
        }

        if (query.isColumnNull(0)) {
            co_return std::nullopt;
        }
        std::string ip_str = query.getColumn(0);
        auto ip = boost::asio::ip::make_address(ip_str);

        NodeAddress address{ip};
        if (!query.isColumnNull(1))
            address.port_disc = query.getColumn(1);
        if (!query.isColumnNull(2))
            address.port_rlpx = query.getColumn(2);

        co_return address;
    }

    Task<std::optional<NodeAddress>> find_node_address_v4(NodeId id) override {
        static const char* sql = R"sql(
            SELECT
                ip,
                port_disc,
                port_rlpx
            FROM nodes
            WHERE id = ?
        )sql";

        return find_node_address(id, sql);
    }

    Task<std::optional<NodeAddress>> find_node_address_v6(NodeId id) override {
        static const char* sql = R"sql(
            SELECT
                ip_v6,
                ip_v6_port_disc,
                ip_v6_port_rlpx
            FROM nodes
            WHERE id = ?
        )sql";

        return find_node_address(id, sql);
    }

    Task<void> update_last_ping_time(NodeId id, Time value) override {
        static const char* sql = R"sql(
            UPDATE nodes SET last_ping_time = ? WHERE id = ?
        )sql";

        SQLite::Statement statement{*db_, sql};
        statement.bind(1, static_cast<int64_t>(unix_timestamp_from_time_point(value)));
        statement.bind(2, id.hex());

        statement.exec();
        co_return;
    }

    Task<std::optional<Time>> find_last_ping_time(NodeId id) override {
        static const char* sql = R"sql(
            SELECT last_ping_time FROM nodes WHERE id = ?
        )sql";

        SQLite::Statement query{*db_, sql};
        query.bind(1, id.hex());

        if (!query.executeStep()) {
            co_return std::nullopt;
        }

        if (query.isColumnNull(0)) {
            co_return std::nullopt;
        }
        int64_t value = query.getColumn(0);

        co_return time_point_from_unix_timestamp(static_cast<uint64_t>(value));
    }

    Task<void> update_last_pong_time(NodeId id, Time value) override {
        static const char* sql = R"sql(
            UPDATE nodes SET last_pong_time = ? WHERE id = ?
        )sql";

        SQLite::Statement statement{*db_, sql};
        statement.bind(1, static_cast<int64_t>(unix_timestamp_from_time_point(value)));
        statement.bind(2, id.hex());

        statement.exec();
        co_return;
    }

    Task<std::optional<Time>> find_last_pong_time(NodeId id) override {
        static const char* sql = R"sql(
            SELECT last_pong_time FROM nodes WHERE id = ?
        )sql";

        SQLite::Statement query{*db_, sql};
        query.bind(1, id.hex());

        if (!query.executeStep()) {
            co_return std::nullopt;
        }

        if (query.isColumnNull(0)) {
            co_return std::nullopt;
        }
        int64_t value = query.getColumn(0);

        co_return time_point_from_unix_timestamp(static_cast<uint64_t>(value));
    }

    Task<void> update_distance(NodeId id, size_t value) override {
        static const char* sql = R"sql(
            UPDATE nodes SET distance = ? WHERE id = ?
        )sql";

        SQLite::Statement statement{*db_, sql};
        statement.bind(1, static_cast<int64_t>(value));
        statement.bind(2, id.hex());

        statement.exec();
        co_return;
    }

    Task<std::optional<size_t>> find_distance(NodeId id) override {
        static const char* sql = R"sql(
            SELECT distance FROM nodes WHERE id = ?
        )sql";

        SQLite::Statement query{*db_, sql};
        query.bind(1, id.hex());

        if (!query.executeStep()) {
            co_return std::nullopt;
        }

        if (query.isColumnNull(0)) {
            co_return std::nullopt;
        }
        int64_t value = query.getColumn(0);

        co_return static_cast<size_t>(value);
    }

    Task<void> delete_node(NodeId id) override {
        static const char* sql = R"sql(
            DELETE FROM nodes WHERE id = ?
        )sql";

        SQLite::Statement statement{*db_, sql};
        statement.bind(1, id.hex());
        statement.exec();
        co_return;
    }

  private:
    std::unique_ptr<SQLite::Database> db_;
};

NodeDbSqlite::NodeDbSqlite(boost::asio::any_io_executor executor)
    : p_impl_(std::make_unique<NodeDbSqliteImpl>()),
      interface_(std::make_unique<SerialNodeDb>(*p_impl_, std::move(executor))) {
}

NodeDbSqlite::~NodeDbSqlite() {
    log::Trace("sentry") << "silkworm::sentry::discovery::node_db::NodeDbSqlite::~NodeDbSqlite";
}

void NodeDbSqlite::setup(const std::filesystem::path& db_dir_path) {
    p_impl_->setup(db_dir_path);
}

void NodeDbSqlite::setup_in_memory() {
    p_impl_->setup_in_memory();
}

NodeDb& NodeDbSqlite::interface() {
    return *interface_;
}

}  // namespace silkworm::sentry::discovery::node_db
