/*
   Copyright 2020 The Silkworm Authors

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

#include <boost/filesystem.hpp>
#include <silkworm/common/log.hpp>
#include <queue>
#include <iomanip>

namespace silkworm::etl {

namespace fs = boost::filesystem;

Collector::~Collector() {

    file_providers_.clear();  // Will ensure all files (if any) have been orderly closed and deleted before we remove
                              // the working dir
    fs::path path(work_path_);
    if (fs::exists(path)) {
        fs::remove_all(path);
    }
}

void Collector::flush_buffer() {
    if (buffer_.size()) {
        buffer_.sort();
        file_providers_.emplace_back(new FileProvider(work_path_, file_providers_.size()));
        file_providers_.back()->flush(buffer_);
        buffer_.clear();
    }
}

size_t Collector::size() const {
    return size_;
}

void Collector::collect(Entry& entry) {
    buffer_.put(entry);
    size_++;
    if (buffer_.overflows()) {
        flush_buffer();
    }
}

void Collector::load(silkworm::lmdb::Table* table, LoadFunc load_func, unsigned int db_flags, bool log_progress) {

    const auto overall_size{size()}; // Amount of work
    uint32_t progress_percent{0};
    uint32_t progress_step{5};  // 5% increment among batches
    size_t progress_segment_size{overall_size / (100 / progress_step)};

    if (!file_providers_.size()) {
        buffer_.sort();
        if (load_func) {
            for (const auto& etl_entry : buffer_.get_entries()) {
                auto trasformed_etl_entries{load_func(etl_entry)};
                for (const auto& transformed_etl_entry : trasformed_etl_entries) {
                    table->put(transformed_etl_entry.key, transformed_etl_entry.value, db_flags);
                }
                if (!--progress_segment_size) {
                    progress_percent += progress_step;
                    progress_segment_size = overall_size / (100 / progress_step);
                    SILKWORM_LOG(LogInfo) << "Load Progress "
                                          << " << " << progress_percent << "%" << std::endl;
                }
            }
        } else {
            for (const auto& etl_entry : buffer_.get_entries()) {
                table->put(etl_entry.key, etl_entry.value, db_flags);
                if (!--progress_segment_size) {
                    progress_percent += progress_step;
                    progress_segment_size = overall_size / (100 / progress_step);
                    SILKWORM_LOG(LogInfo) << "Load Progress "
                        << " << " << progress_percent << "%" << std::endl;
                }
            }
        }
        buffer_.clear();
        return;
    }

    // Flush not overflown buffer data to file
    flush_buffer();

    // Define a priority queue based on smallest available key
    auto key_comparer = [](std::pair<Entry, int> left, std::pair<Entry, int> right) {
        return left.first.key.compare(right.first.key) > 0;
    };
    std::priority_queue<std::pair<Entry, int>, std::vector<std::pair<Entry, int>>, decltype(key_comparer)> queue(
        key_comparer);

    // Read one "record" from each data_provider and let the queue
    // sort them. On top of the queue the smallest key
    for (auto& file_provider : file_providers_) {
        auto item{file_provider->read_entry()};
        if (item.has_value()) {
            queue.push(*item);
        }
    }

    // Process the queue from smallest to largest key
    while (queue.size()) {
        auto& [etl_entry, provider_index]{queue.top()};           // Pick smallest key by reference
        auto& file_provider{file_providers_.at(provider_index)};  // and set current file provider

        // Process linked pairs
        if (load_func) {
            for (const auto& transformed_etl_entry : load_func(etl_entry)) {
                table->put(transformed_etl_entry.key, transformed_etl_entry.value, db_flags);
            }
        } else {
            table->put(etl_entry.key, etl_entry.value, db_flags);
        }

        // Display progress
        if (!--progress_segment_size) {
            progress_percent += progress_step;
            progress_segment_size = overall_size / (100 / progress_step);
            SILKWORM_LOG(LogInfo) << "Load Progress "
                << " << " << progress_percent << "%" << std::endl;
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
            queue.push(*next);
        } else {
            file_provider.reset();
        }
    }
}

std::string Collector::set_work_path(const char* provided_work_path) {
    // If something provided ensure exists as a directory
    if (provided_work_path) {
        fs::path path(provided_work_path);
        if (!fs::exists(path) || !fs::is_directory(path)) {
            throw etl_error("Non existent working directory");
        }
        return path.string();
    }

    // No path provided so we need to get a unique temporary directory
    // to prevent different instances of collector to clash each other
    // with same filenames
    fs::path p{fs::temp_directory_path() / fs::unique_path()};
    fs::create_directories(p);
    return p.string();
}

std::vector<Entry> identity_load(Entry entry) { return std::vector<Entry>({entry}); }

}  // namespace silkworm::etl
