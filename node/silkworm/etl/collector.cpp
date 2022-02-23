/*
    Copyright 2020-2022 The Silkworm Authors

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

#include "collector.hpp"

#include <filesystem>
#include <iomanip>
#include <queue>

#include <silkworm/common/directories.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/concurrency/signal_handler.hpp>

namespace silkworm::etl {

namespace fs = std::filesystem;

Collector::~Collector() {
    clear();  // Will ensure all files (if any) have been orderly closed and deleted
    if (work_path_managed_ && fs::exists(work_path_)) {
        fs::remove_all(work_path_);
    }
}

void Collector::flush_buffer() {
    if (buffer_.size()) {
        buffer_.sort();

        /* Build a unique file name to pass FileProvider */
        fs::path new_file_path{
            work_path_ / fs::path(std::to_string(unique_id_) + "-" + std::to_string(file_providers_.size()) + ".bin")};

        file_providers_.emplace_back(new FileProvider(new_file_path.string(), file_providers_.size()));
        file_providers_.back()->flush(buffer_);
        buffer_.clear();
        log::Info("Collector flushed file", {"path", std::string(file_providers_.back()->get_file_name()), "size",
                                             human_size(file_providers_.back()->get_file_size())});
    }
}

void Collector::collect(const Entry& entry) {
    buffer_.put(entry);
    ++size_;
    if (buffer_.overflows()) {
        flush_buffer();
    }
}

void Collector::collect(Entry&& entry) {
    buffer_.put(std::move(entry));
    ++size_;
    if (buffer_.overflows()) {
        flush_buffer();
    }
}

void Collector::load(mdbx::cursor& target, const LoadFunc& load_func, MDBX_put_flags_t flags) {
    size_t counter{32};  // Every 32 entry we track the key being loaded
    set_loading_key({});

    if (empty()) {
        return;
    }

    if (file_providers_.empty()) {
        buffer_.sort();

        for (const auto& etl_entry : buffer_.entries()) {
            if (!--counter) {
                if (SignalHandler::signalled()) {
                    throw std::runtime_error("Operation cancelled");
                }
                counter = 32;
                set_loading_key(etl_entry.key);
            }
            if (load_func) {
                load_func(etl_entry, target, flags);
            } else {
                mdbx::slice k{db::to_slice(etl_entry.key)};

                if (etl_entry.value.empty()) {
                    target.erase(k);
                } else {
                    mdbx::slice v{db::to_slice(etl_entry.value)};
                    mdbx::error::success_or_throw(target.put(k, &v, flags));
                }
            }
        }

        size_ = 0;
        buffer_.clear();
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

        if (!--counter) {
            if (SignalHandler::signalled()) {
                throw std::runtime_error("Operation cancelled");
            }
            counter = 32;
            set_loading_key(etl_entry.key);
        }

        // Process linked pairs
        if (load_func) {
            load_func(etl_entry, target, flags);
        } else {
            mdbx::slice k{db::to_slice(etl_entry.key)};
            mdbx::slice v{db::to_slice(etl_entry.value)};
            mdbx::error::success_or_throw(target.put(k, &v, flags));
        }

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
    size_ = 0;  // We have consumed all items
}

std::filesystem::path Collector::set_work_path(const std::optional<std::filesystem::path>& provided_work_path) {
    fs::path res;

    // If something provided ensure exists as a directory
    if (provided_work_path.has_value()) {
        if (fs::exists(provided_work_path.value()) && !fs::is_directory(provided_work_path.value())) {
            throw etl_error("Invalid collector directory name");
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

}  // namespace silkworm::etl
