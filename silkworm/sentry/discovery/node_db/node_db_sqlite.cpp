// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "node_db_sqlite.hpp"

#include <algorithm>
#include <sstream>
#include <stdexcept>
#include <string>

#include <SQLiteCpp/SQLiteCpp.h>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/common/unix_timestamp.hpp>

#include "serial_node_db.hpp"

namespace silkworm::sentry::discovery::node_db {

static constexpr const char* kSqlCreateSchema = R"sql(

PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS nodes (
    id TEXT PRIMARY KEY,

    ip TEXT,
    port_disc INTEGER,
    port_rlpx INTEGER,
    ip_v6 TEXT,
    ip_v6_port_disc INTEGER,
    ip_v6_port_rlpx INTEGER,

    next_ping_time INTEGER,
    last_pong_time INTEGER,
    ping_fails INTEGER NOT NULL DEFAULT 0,
    lookup_time INTEGER,

    peer_disconnected_time INTEGER,
    peer_is_useless INTEGER,
    taken_time INTEGER,

    enr_seq_num INTEGER,
    eth1_fork_id BLOB,

    distance INTEGER NON NULL DEFAULT 256
);

CREATE INDEX IF NOT EXISTS idx_nodes_ip ON nodes (ip);
CREATE INDEX IF NOT EXISTS idx_nodes_ip_v6 ON nodes (ip_v6);
CREATE INDEX IF NOT EXISTS idx_next_ping_time ON nodes (next_ping_time);
CREATE INDEX IF NOT EXISTS idx_last_pong_time ON nodes (last_pong_time);
CREATE INDEX IF NOT EXISTS idx_lookup_time ON nodes (lookup_time);
CREATE INDEX IF NOT EXISTS idx_peer_disconnected_time ON nodes (peer_disconnected_time);
CREATE INDEX IF NOT EXISTS idx_peer_is_useless ON nodes (peer_is_useless);
CREATE INDEX IF NOT EXISTS idx_taken_time ON nodes (taken_time);
CREATE INDEX IF NOT EXISTS idx_distance ON nodes (distance);

)sql";

/**
 * Replaces `placeholder` in `sql` with `count` comma-separated question marks, e.g.: "?,?,?"
 * If `count` is zero, `placeholder` is replaced with an `empty_value`.
 */
static std::string replace_placeholders(
    const char* sql_template,
    std::string_view placeholder,
    size_t count,
    std::string_view empty_value) {
    std::string placeholders;
    if (count > 0) {
        std::ostringstream placeholders_stream;
        std::fill_n(std::ostream_iterator<std::string>(placeholders_stream), count, "?,");
        placeholders = placeholders_stream.str();
        placeholders.pop_back();  // remove the last comma
    } else {
        placeholders = empty_value;
    }

    std::string sql{sql_template};
    sql.replace(sql.find(placeholder), placeholder.size(), placeholders);
    return sql;
}

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

    Task<bool> upsert_node_address(NodeId id, NodeAddress address) override {
        static constexpr const char* kSqlIpV4 = R"sql(
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

        static constexpr const char* kSqlIpV6 = R"sql(
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

        static constexpr const char* kExistsSql = R"sql(
            SELECT 1 FROM nodes WHERE id = ?
        )sql";

        SQLite::Statement exists_query{*db_, kExistsSql};
        exists_query.bind(1, id.hex());

        const char* sql = nullptr;
        if (address.ip.is_v4()) {
            sql = kSqlIpV4;
        }
        if (address.ip.is_v6()) {
            sql = kSqlIpV6;
        }
        SILKWORM_ASSERT(sql);
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

        SQLite::Transaction transaction{*db_};
        bool exists = exists_query.executeStep();
        statement.exec();
        transaction.commit();
        co_return !exists;
    }

    Task<std::optional<NodeAddress>> find_node_address_sql(NodeId id, const char* sql) {
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

        NodeAddress address{std::move(ip)};
        if (!query.isColumnNull(1))
            address.port_disc = query.getColumn(1);
        if (!query.isColumnNull(2))
            address.port_rlpx = query.getColumn(2);

        co_return address;
    }

    Task<std::optional<NodeAddress>> find_node_address_v4(NodeId id) override {
        static constexpr const char* kSql = R"sql(
            SELECT
                ip,
                port_disc,
                port_rlpx
            FROM nodes
            WHERE id = ?
        )sql";

        return find_node_address_sql(id, kSql);
    }

    Task<std::optional<NodeAddress>> find_node_address_v6(NodeId id) override {
        static constexpr const char* kSql = R"sql(
            SELECT
                ip_v6,
                ip_v6_port_disc,
                ip_v6_port_rlpx
            FROM nodes
            WHERE id = ?
        )sql";

        return find_node_address_sql(id, kSql);
    }

    Task<void> update_next_ping_time(NodeId id, Time value) override {
        static constexpr const char* kSql = R"sql(
            UPDATE nodes SET next_ping_time = ? WHERE id = ?
        )sql";

        set_node_property_time(id, kSql, value);
        co_return;
    }

    Task<std::optional<Time>> find_next_ping_time(NodeId id) override {
        static constexpr const char* kSql = R"sql(
            SELECT next_ping_time FROM nodes WHERE id = ?
        )sql";

        co_return get_node_property_time(id, kSql);
    }

    Task<void> update_last_pong_time(NodeId id, Time value) override {
        static constexpr const char* kSql = R"sql(
            UPDATE nodes SET last_pong_time = ? WHERE id = ?
        )sql";

        set_node_property_time(id, kSql, value);
        co_return;
    }

    Task<std::optional<Time>> find_last_pong_time(NodeId id) override {
        static constexpr const char* kSql = R"sql(
            SELECT last_pong_time FROM nodes WHERE id = ?
        )sql";

        co_return get_node_property_time(id, kSql);
    }

    Task<void> update_ping_fails(NodeId id, size_t value) override {
        static constexpr const char* kSql = R"sql(
            UPDATE nodes SET ping_fails = ? WHERE id = ?
        )sql";

        set_node_property_int(id, kSql, static_cast<int64_t>(value));
        co_return;
    }

    Task<std::optional<size_t>> find_ping_fails(NodeId id) override {
        static constexpr const char* kSql = R"sql(
            SELECT ping_fails FROM nodes WHERE id = ?
        )sql";

        auto value = get_node_property_int(id, kSql);
        if (value) {
            co_return static_cast<size_t>(*value);
        } else {
            co_return std::nullopt;
        }
    }

    Task<void> update_peer_disconnected_time(NodeId id, Time value) override {
        static constexpr const char* kSql = R"sql(
            UPDATE nodes SET peer_disconnected_time = ? WHERE id = ?
        )sql";

        set_node_property_time(id, kSql, value);
        co_return;
    }

    Task<std::optional<Time>> find_peer_disconnected_time(NodeId id) override {
        static constexpr const char* kSql = R"sql(
            SELECT peer_disconnected_time FROM nodes WHERE id = ?
        )sql";

        co_return get_node_property_time(id, kSql);
    }

    Task<void> update_peer_is_useless(NodeId id, bool value) override {
        static constexpr const char* kSql = R"sql(
            UPDATE nodes SET peer_is_useless = ? WHERE id = ?
        )sql";

        set_node_property_int(id, kSql, value ? 1 : 0);
        co_return;
    }

    Task<std::optional<bool>> find_peer_is_useless(NodeId id) override {
        static constexpr const char* kSql = R"sql(
            SELECT peer_is_useless FROM nodes WHERE id = ?
        )sql";

        auto value = get_node_property_int(id, kSql);
        if (value) {
            co_return *value;
        } else {
            co_return std::nullopt;
        }
    }

    Task<void> update_distance(NodeId id, size_t value) override {
        static constexpr const char* kSql = R"sql(
            UPDATE nodes SET distance = ? WHERE id = ?
        )sql";

        set_node_property_int(id, kSql, static_cast<int64_t>(value));
        co_return;
    }

    Task<std::optional<size_t>> find_distance(NodeId id) override {
        static constexpr const char* kSql = R"sql(
            SELECT distance FROM nodes WHERE id = ?
        )sql";

        auto value = get_node_property_int(id, kSql);
        if (value) {
            co_return static_cast<size_t>(*value);
        } else {
            co_return std::nullopt;
        }
    }

    Task<void> update_enr_seq_num(NodeId id, uint64_t value) override {
        static constexpr const char* kSql = R"sql(
            UPDATE nodes SET enr_seq_num = ? WHERE id = ?
        )sql";

        set_node_property_int(id, kSql, static_cast<int64_t>(value));
        co_return;
    }

    Task<std::optional<uint64_t>> find_enr_seq_num(NodeId id) override {
        static constexpr const char* kSql = R"sql(
            SELECT enr_seq_num FROM nodes WHERE id = ?
        )sql";

        auto value = get_node_property_int(id, kSql);
        if (value) {
            co_return static_cast<uint64_t>(*value);
        } else {
            co_return std::nullopt;
        }
    }

    Task<void> update_eth1_fork_id(NodeId id, std::optional<Bytes> value) override {
        static constexpr const char* kSql = R"sql(
            UPDATE nodes SET eth1_fork_id = ? WHERE id = ?
        )sql";

        SQLite::Statement statement{*db_, kSql};
        if (value) {
            statement.bindNoCopy(1, value->data(), static_cast<int>(value->size()));
        } else {
            statement.bind(1);
        }
        statement.bind(2, id.hex());
        statement.exec();
        co_return;
    }

    Task<std::optional<Bytes>> find_eth1_fork_id(NodeId id) override {
        static constexpr const char* kSql = R"sql(
            SELECT eth1_fork_id FROM nodes WHERE id = ?
        )sql";

        SQLite::Statement query{*db_, kSql};
        query.bind(1, id.hex());

        if (!query.executeStep()) {
            co_return std::nullopt;
        }

        if (query.isColumnNull(0)) {
            co_return std::nullopt;
        }
        Bytes value{
            reinterpret_cast<const uint8_t*>(query.getColumn(0).getBlob()),
            static_cast<size_t>(query.getColumn(0).size()),
        };
        co_return std::move(value);
    }

    Task<std::vector<NodeId>> find_ping_candidates(Time time, size_t limit) override {
        static constexpr const char* kSql = R"sql(
            SELECT id FROM nodes
            WHERE ((next_ping_time IS NULL) OR (next_ping_time < ?))
                AND ((peer_is_useless IS NULL) OR (peer_is_useless == 0))
            ORDER BY next_ping_time
            LIMIT ?
        )sql";

        SQLite::Statement query{*db_, kSql};
        query.bind(1, static_cast<int64_t>(unix_timestamp_from_time_point(time)));
        query.bind(2, static_cast<int64_t>(limit));

        std::vector<NodeId> ids;
        while (query.executeStep()) {
            std::string id_hex = query.getColumn(0);
            auto id = EccPublicKey::deserialize_hex(id_hex);
            ids.push_back(std::move(id));
        }

        co_return ids;
    }

    Task<std::vector<NodeId>> find_useful_nodes(Time min_pong_time, size_t limit) override {
        static constexpr const char* kSql = R"sql(
            SELECT id FROM nodes
            WHERE ((last_pong_time IS NOT NULL) AND (last_pong_time > ?))
                AND ((peer_is_useless IS NULL) OR (peer_is_useless == 0))
            ORDER BY RANDOM()
            LIMIT ?
        )sql";

        SQLite::Statement query{*db_, kSql};
        query.bind(1, static_cast<int64_t>(unix_timestamp_from_time_point(min_pong_time)));
        query.bind(2, static_cast<int64_t>(limit));

        std::vector<NodeId> ids;
        while (query.executeStep()) {
            std::string id_hex = query.getColumn(0);
            auto id = EccPublicKey::deserialize_hex(id_hex);
            ids.push_back(std::move(id));
        }

        co_return ids;
    }

    Task<std::vector<NodeId>> find_lookup_candidates(FindLookupCandidatesQuery query_params) override {
        static constexpr const char* kSql = R"sql(
            SELECT id FROM nodes
            WHERE ((last_pong_time IS NOT NULL) AND (last_pong_time > ?))
                AND ((peer_is_useless IS NULL) OR (peer_is_useless == 0))
                AND ((lookup_time IS NULL) OR (lookup_time < ?))
            ORDER BY distance, lookup_time
            LIMIT ?
        )sql";

        SQLite::Statement query{*db_, kSql};
        query.bind(1, static_cast<int64_t>(unix_timestamp_from_time_point(query_params.min_pong_time)));
        query.bind(2, static_cast<int64_t>(unix_timestamp_from_time_point(query_params.max_lookup_time)));
        query.bind(3, static_cast<int64_t>(query_params.limit));

        std::vector<NodeId> ids;
        while (query.executeStep()) {
            std::string id_hex = query.getColumn(0);
            auto id = EccPublicKey::deserialize_hex(id_hex);
            ids.push_back(std::move(id));
        }

        co_return ids;
    }

    Task<void> mark_taken_lookup_candidates(const std::vector<NodeId>& ids, Time time) override {
        if (ids.empty())
            co_return;

        static constexpr const char* kSqlTemplate = R"sql(
            UPDATE nodes SET lookup_time = ? WHERE id IN (???)
        )sql";
        auto sql = replace_placeholders(kSqlTemplate, "???", ids.size(), "NULL");

        SQLite::Statement statement{*db_, sql};
        statement.bind(1, static_cast<int64_t>(unix_timestamp_from_time_point(time)));
        for (size_t i = 0; i < ids.size(); ++i) {
            statement.bind(static_cast<int>(i + 2), ids[i].hex());
        }
        statement.exec();
        co_return;
    }

    Task<std::vector<NodeId>> take_lookup_candidates(FindLookupCandidatesQuery query, Time time) override {
        SQLite::Transaction transaction{*db_};
        auto candidates = co_await find_lookup_candidates(query);
        co_await mark_taken_lookup_candidates(candidates, time);
        transaction.commit();
        co_return candidates;
    }

    Task<std::vector<NodeId>> find_peer_candidates(FindPeerCandidatesQuery query_params) override {
        static constexpr const char* kSqlTemplate = R"sql(
            SELECT id FROM nodes
            WHERE ((last_pong_time IS NOT NULL) AND (last_pong_time > ?))
                AND ((peer_disconnected_time IS NULL) OR (peer_disconnected_time < ?))
                AND ((peer_is_useless IS NULL) OR (peer_is_useless == 0))
                AND ((taken_time IS NULL) OR (taken_time < ?))
                AND (id NOT IN (???))
            ORDER BY distance, RANDOM()
            LIMIT :limit
        )sql";
        auto sql = replace_placeholders(kSqlTemplate, "???", query_params.exclude_ids.size(), "''");

        SQLite::Statement query{*db_, sql};
        query.bind(1, static_cast<int64_t>(unix_timestamp_from_time_point(query_params.min_pong_time)));
        query.bind(2, static_cast<int64_t>(unix_timestamp_from_time_point(query_params.max_peer_disconnected_time)));
        query.bind(3, static_cast<int64_t>(unix_timestamp_from_time_point(query_params.max_taken_time)));
        for (size_t i = 0; i < query_params.exclude_ids.size(); ++i) {
            query.bind(static_cast<int>(i + 4), query_params.exclude_ids[i].hex());
        }
        query.bind(":limit", static_cast<int64_t>(query_params.limit));

        std::vector<NodeId> ids;
        while (query.executeStep()) {
            std::string id_hex = query.getColumn(0);
            auto id = EccPublicKey::deserialize_hex(id_hex);
            ids.push_back(std::move(id));
        }

        co_return ids;
    }

    Task<void> mark_taken_peer_candidates(const std::vector<NodeId>& ids, Time time) override {
        if (ids.empty())
            co_return;

        static constexpr const char* kSqlTemplate = R"sql(
            UPDATE nodes SET taken_time = ? WHERE id IN (???)
        )sql";
        auto sql = replace_placeholders(kSqlTemplate, "???", ids.size(), "NULL");

        SQLite::Statement statement{*db_, sql};
        statement.bind(1, static_cast<int64_t>(unix_timestamp_from_time_point(time)));
        for (size_t i = 0; i < ids.size(); ++i) {
            statement.bind(static_cast<int>(i + 2), ids[i].hex());
        }
        statement.exec();
        co_return;
    }

    Task<std::vector<NodeId>> take_peer_candidates(FindPeerCandidatesQuery query, Time time) override {
        SQLite::Transaction transaction{*db_};
        auto candidates = co_await find_peer_candidates(std::move(query));
        co_await mark_taken_peer_candidates(candidates, time);
        transaction.commit();
        co_return candidates;
    }

    Task<void> delete_node(NodeId id) override {
        static constexpr const char* kSql = R"sql(
            DELETE FROM nodes WHERE id = ?
        )sql";

        SQLite::Statement statement{*db_, kSql};
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
        if (!value) {
            return std::nullopt;
        }
        return time_point_from_unix_timestamp(static_cast<uint64_t>(*value));
    }

    void set_node_property_time(const NodeId& id, const char* sql, Time value) {
        set_node_property_int(id, sql, static_cast<int64_t>(unix_timestamp_from_time_point(value)));
    }

    std::unique_ptr<SQLite::Database> db_;
};

NodeDbSqlite::NodeDbSqlite(const boost::asio::any_io_executor& executor)
    : p_impl_(std::make_unique<NodeDbSqliteImpl>()),
      interface_(std::make_unique<SerialNodeDb>(*p_impl_, executor)) {
}

NodeDbSqlite::~NodeDbSqlite() {
    SILK_TRACE_M("sentry") << "silkworm::sentry::discovery::node_db::NodeDbSqlite::~NodeDbSqlite";
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
