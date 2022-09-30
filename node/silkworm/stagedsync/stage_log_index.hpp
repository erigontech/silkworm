/*
   Copyright 2022 The Silkworm Authors

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

#include <cbor/cbor.h>

#include <silkworm/db/bitmap.hpp>
#include <silkworm/stagedsync/stage.hpp>

namespace silkworm::stagedsync {

class LogIndex : public Stage {
  public:
    explicit LogIndex(NodeSettings* node_settings, SyncContext* sync_context)
        : Stage(sync_context, db::stages::kLogIndexKey, node_settings){};
    ~LogIndex() override = default;

    Stage::Result forward(db::RWTxn& txn) final;
    Stage::Result unwind(db::RWTxn& txn) final;
    Stage::Result prune(db::RWTxn& txn) final;
    std::vector<std::string> get_log_progress() final;

  private:
    std::unique_ptr<etl::Collector> topics_collector_{nullptr};
    std::unique_ptr<etl::Collector> addresses_collector_{nullptr};
    std::unique_ptr<db::bitmap::IndexLoader> index_loader_{nullptr};

    std::atomic_bool loading_{false};  // Whether we're in ETL loading phase
    std::string current_source_;       // Current source of data
    std::string current_target_;       // Current target of transformed data
    std::string current_key_;          // Actual processing key

    void forward_impl(db::RWTxn& txn, BlockNum from, BlockNum to);
    void unwind_impl(db::RWTxn& txn, BlockNum from, BlockNum to);
    void prune_impl(db::RWTxn& txn, BlockNum threshold, const db::MapConfig& target);

    //! \brief Collects bitmaps of block numbers for each log entry
    void collect_bitmaps_from_logs(db::RWTxn& txn, const db::MapConfig& source_config, BlockNum from, BlockNum to);

    //! \brief Collects unique keys for log entries within provided boundaries
    void collect_unique_keys_from_logs(
        db::RWTxn& txn,
        const db::MapConfig& source_config,
        BlockNum from, BlockNum to,
        std::map<Bytes, bool>& addresses,
        std::map<Bytes, bool>& topics);

    void reset_log_progress();  // Clears out all logging vars

    using cbor_function = std::function<void(unsigned char*, int)>;
    class CborListener : public cbor::listener {
      public:
        explicit CborListener(cbor_function& on_bytes_function) : on_bytes_function_{on_bytes_function} {};

        void on_integer(int) override {}
        void on_bytes(unsigned char* data, int size) override { on_bytes_function_(data, size); };
        void on_string(std::string&) override {}
        void on_array(int) override {}
        void on_map(int) override {}
        void on_tag(unsigned int) override {}
        void on_special(unsigned int) override {}
        void on_bool(bool) override {}
        void on_null() override {}
        void on_undefined() override {}
        void on_error(const char*) override { throw std::runtime_error("Unexpected CBOR decoding error"); }
        void on_extra_integer(unsigned long long, int) override {}
        void on_extra_tag(unsigned long long) override {}
        void on_extra_special(unsigned long long) override {}
        void on_double(double) override {}
        void on_float32(float) override {}

      private:
        cbor_function& on_bytes_function_;
    };
};

}  // namespace silkworm::stagedsync
