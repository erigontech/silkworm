// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "collector.hpp"

#include <filesystem>
#include <iomanip>
#include <queue>
#include <stdexcept>

#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/common/stopwatch.hpp>
#include <silkworm/infra/concurrency/signal_handler.hpp>

namespace silkworm::datastore::etl {

namespace fs = std::filesystem;

Collector::~Collector() {
    clear();  // Will ensure all files (if any) have been orderly closed and deleted
    if (work_path_managed_ && fs::exists(work_path_)) {
        fs::remove_all(work_path_);
    }
}

void Collector::flush_buffer() {
    if (buffer_.size()) {
        StopWatch sw(/*auto_start=*/true);
        buffer_.sort();

        /* Build a unique file name to pass FileProvider */
        fs::path new_file_path{
            work_path_ / fs::path(std::to_string(unique_id_) + "-" + std::to_string(file_providers_.size()) + ".bin")};

        file_providers_.emplace_back(new FileProvider(new_file_path.string(), file_providers_.size()));
        file_providers_.back()->flush(buffer_);
        buffer_.clear();
        const auto [_, duration]{sw.stop()};
        log::Debug(
            "ETL collector flushed file",
            {
                "path",
                std::string(file_providers_.back()->get_file_name()),
                "size",
                human_size(file_providers_.back()->get_file_size()),
                "in",
                StopWatch::format(duration),
            });
    }
}

void Collector::collect(Entry entry) {
    ++size_;
    bytes_size_ += entry.size();
    buffer_.put(std::move(entry));
    if (buffer_.overflows()) {
        flush_buffer();
    }
}

void Collector::collect(Bytes key, Bytes value) {
    collect(Entry{std::move(key), std::move(value)});
}

void Collector::load(const LoadFunc& load_func) {
    using namespace std::chrono_literals;
    static constexpr std::chrono::seconds kLogInterval{5s};  // Updates processing key (for log purposes) every this time
    auto log_time{std::chrono::steady_clock::now()};         // To check if an update of key is needed

    set_loading_key({});

    if (empty()) {
        return;
    }

    if (file_providers_.empty()) {
        buffer_.sort();

        for (const auto& etl_entry : buffer_.entries()) {
            if (const auto now{std::chrono::steady_clock::now()}; log_time <= now) {
                if (SignalHandler::signalled()) {
                    throw std::runtime_error("Operation cancelled");
                }
                set_loading_key(etl_entry.key);
                log_time = now + kLogInterval;
            }
            load_func(etl_entry);
        }

        clear();
        return;
    }

    // Flush not overflown buffer data to file
    flush_buffer();

    // Define a priority queue based on smallest available key
    auto key_comparer = [](const std::pair<Entry, size_t>& left, const std::pair<Entry, size_t>& right) {
        return right.first < left.first;
    };
    std::priority_queue<std::pair<Entry, size_t>, std::vector<std::pair<Entry, size_t>>, decltype(key_comparer)> queue(
        key_comparer);

    // Read one "record" from each data_provider and let the queue
    // sort them. On top of the queue the smallest key
    for (auto& file_provider : file_providers_) {
        auto item{file_provider->read_entry()};
        if (item.has_value()) {
            queue.push(std::move(*item));
        }
    }

    // Process the queue from smallest to largest key
    while (!queue.empty()) {
        auto& [etl_entry, provider_index]{queue.top()};           // Pick the smallest key by reference
        auto& file_provider{file_providers_.at(provider_index)};  // and set current file provider

        if (const auto now{std::chrono::steady_clock::now()}; log_time <= now) {
            if (SignalHandler::signalled()) {
                throw std::runtime_error("Operation cancelled");
            }
            log_time = now + kLogInterval;
            set_loading_key(etl_entry.key);
        }

        // Process linked pairs
        load_func(etl_entry);

        // From the provider which has served the current key
        // read next "record"
        auto next{file_provider->read_entry()};

        // At this point `current` has been processed.
        // We can remove it from the queue
        queue.pop();

        // Add next item to the queue only if it has
        // meaningful data
        if (next.has_value()) {
            queue.push(std::move(*next));
        } else {
            file_provider.reset();
        }
    }
    clear();
}

std::filesystem::path Collector::set_work_path(const std::optional<std::filesystem::path>& provided_work_path) {
    fs::path res;

    // If something provided ensure exists as a directory
    if (provided_work_path.has_value()) {
        if (fs::exists(provided_work_path.value()) && !fs::is_directory(provided_work_path.value())) {
            throw EtlError("Invalid collector directory name");
        }
        res = provided_work_path.value();
    } else {
        // No path provided we need to get a unique temporary directory
        // to prevent different instances of collector to clash each other
        // with same filenames
        res = TemporaryDirectory::get_unique_temporary_path();
    }
    if (res.has_filename()) {
        res += std::filesystem::path::preferred_separator;
    }
    fs::create_directories(res);
    return res;
}

}  // namespace silkworm::datastore::etl
