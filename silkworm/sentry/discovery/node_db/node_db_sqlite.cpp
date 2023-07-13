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

#include <algorithm>
#include <cassert>
#include <sstream>
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

    peer_disconnected_time INTEGER,
    peer_is_useless INTEGER,

    taken_time INTEGER,

    distance INTEGER NON NULL DEFAULT 256
);

CREATE INDEX IF NOT EXISTS idx_nodes_ip ON nodes (ip);
CREATE INDEX IF NOT EXISTS idx_nodes_ip_v6 ON nodes (ip_v6);
CREATE INDEX IF NOT EXISTS idx_last_ping_time ON nodes (last_ping_time);
CREATE INDEX IF NOT EXISTS idx_last_pong_time ON nodes (last_pong_time);
CREATE INDEX IF NOT EXISTS idx_peer_disconnected_time ON nodes (peer_disconnected_time);
CREATE INDEX IF NOT EXISTS idx_peer_is_useless ON nodes (peer_is_useless);
CREATE INDEX IF NOT EXISTS idx_taken_time ON nodes (taken_time);
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

        set_node_property_time(id, sql, value);
        co_return;
    }

    Task<std::optional<Time>> find_last_ping_time(NodeId id) override {
        static const char* sql = R"sql(
            SELECT last_ping_time FROM nodes WHERE id = ?
        )sql";

        co_return get_node_property_time(id, sql);
    }

    Task<void> update_last_pong_time(NodeId id, Time value) override {
        static const char* sql = R"sql(
            UPDATE nodes SET last_pong_time = ? WHERE id = ?
        )sql";

        set_node_property_time(id, sql, value);
        co_return;
    }

    Task<std::optional<Time>> find_last_pong_time(NodeId id) override {
        static const char* sql = R"sql(
            SELECT last_pong_time FROM nodes WHERE id = ?
        )sql";

        co_return get_node_property_time(id, sql);
    }

    Task<void> update_peer_disconnected_time(NodeId id, Time value) override {
        static const char* sql = R"sql(
            UPDATE nodes SET peer_disconnected_time = ? WHERE id = ?
        )sql";

        set_node_property_time(id, sql, value);
        co_return;
    }

    Task<std::optional<Time>> find_peer_disconnected_time(NodeId id) override {
        static const char* sql = R"sql(
            SELECT peer_disconnected_time FROM nodes WHERE id = ?
        )sql";

        co_return get_node_property_time(id, sql);
    }

    Task<void> update_peer_is_useless(NodeId id, bool value) override {
        static const char* sql = R"sql(
            UPDATE nodes SET peer_is_useless = ? WHERE id = ?
        )sql";

        set_node_property_int(id, sql, value ? 1 : 0);
        co_return;
    }

    Task<std::optional<bool>> find_peer_is_useless(NodeId id) override {
        static const char* sql = R"sql(
            SELECT peer_is_useless FROM nodes WHERE id = ?
        )sql";

        auto value = get_node_property_int(id, sql);
        if (value) {
            co_return *value;
        } else {
            co_return std::nullopt;
        }
    }

    Task<void> update_distance(NodeId id, size_t value) override {
        static const char* sql = R"sql(
            UPDATE nodes SET distance = ? WHERE id = ?
        )sql";

        set_node_property_int(id, sql, static_cast<int64_t>(value));
        co_return;
    }

    Task<std::optional<size_t>> find_distance(NodeId id) override {
        static const char* sql = R"sql(
            SELECT distance FROM nodes WHERE id = ?
        )sql";

        auto value = get_node_property_int(id, sql);
        if (value) {
            co_return static_cast<size_t>(*value);
        } else {
            co_return std::nullopt;
        }
    }

    Task<std::vector<NodeId>> find_peer_candidates(size_t limit) override {
        // TODO
        co_return std::vector<NodeId>{};
    }

    Task<void> mark_taken_peer_candidates(const std::vector<NodeId>& ids, Time time) override {
        if (ids.empty())
            co_return;

        static const char* sql_template = R"sql(
            UPDATE nodes SET taken_time = ? WHERE id IN (???)
        )sql";

        std::ostringstream placeholders_stream;
        std::fill_n(std::ostream_iterator<std::string>(placeholders_stream), ids.size(), "?,");
        auto placeholders = placeholders_stream.str();
        placeholders.pop_back();  // remove the last comma

        std::string sql{sql_template};
        sql.replace(sql.find("???"), 3, placeholders);

        SQLite::Statement statement{*db_, sql};
        statement.bind(1, static_cast<int64_t>(unix_timestamp_from_time_point(time)));
        for (size_t i = 0; i < ids.size(); i++) {
            statement.bind(static_cast<int>(i + 2), ids[i].hex());
        }
        statement.exec();
        co_return;
    }

    Task<std::vector<NodeId>> take_peer_candidates(size_t limit, Time time) override {
        SQLite::Transaction transaction{*db_};
        auto candidates = co_await find_peer_candidates(limit);
        co_await mark_taken_peer_candidates(candidates, time);
        transaction.commit();
        co_return candidates;
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
    std::optional<int64_t> get_node_property_int(const NodeId& id, const char* sql) {
        SQLite::Statement query{*db_, sql};
        query.bind(1, id.hex());

        if (!query.executeStep()) {
            return std::nullopt;
        }

        if (query.isColumnNull(0)) {
            return std::nullopt;
        }
        int64_t value = query.getColumn(0);
        return {value};
    }

    void set_node_property_int(const NodeId& id, const char* sql, int64_t value) {
        SQLite::Statement statement{*db_, sql};
        statement.bind(1, value);
        statement.bind(2, id.hex());
        statement.exec();
    }

    std::optional<Time> get_node_property_time(const NodeId& id, const char* sql) {
        auto value = get_node_property_int(id, sql);
        if (value) {
            return time_point_from_unix_timestamp(static_cast<uint64_t>(*value));
        } else {
            return std::nullopt;
        }
    }

    void set_node_property_time(const NodeId& id, const char* sql, Time value) {
        set_node_property_int(id, sql, static_cast<int64_t>(unix_timestamp_from_time_point(value)));
    }

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
