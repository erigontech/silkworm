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

#include <queue>
#include <boost/filesystem.hpp>

namespace silkworm::etl {

    namespace fs = boost::filesystem;

    Collector::~Collector()
    {
        if (work_path_.empty()) {
            return;
        }

        fs::path path(work_path_);
        if (fs::exists(path)) {
            fs::remove_all(path);
        }
    }


    void Collector::flush_buffer() {
    if (buffer_.size()) {
        buffer_.sort();
        file_providers_.emplace_back(work_path_, (int)file_providers_.size());
        file_providers_.back().flush(buffer_);
        buffer_.clear();
    }
}

void Collector::collect(Entry& entry) {
    buffer_.put(entry);
    if (buffer_.overflows()) {
        flush_buffer();
    }
}

void Collector::load(silkworm::lmdb::Table* table, Load load) {

    if (!file_providers_.size()) {
        buffer_.sort();
        for (const auto& entry : buffer_.get_entries()) {
            auto entries{load(entry)};
            for (const auto& entry2 : entries) {
                table->put(entry2.key, entry2.value);
            }
        }
        buffer_.clear();
        return;
    }

    flush_buffer();

    // Define a priority queue based on smallest available key
    auto key_comparer = [](std::pair<Entry, int> left, std::pair<Entry, int> right) {
        return left.first.key.compare(right.first.key) > 0;
    };
    std::priority_queue<std::pair<Entry, int>, std::vector<std::pair<Entry, int>>,
                        decltype(key_comparer)>
        queue(key_comparer);

    // Read one "record" from each data_provider and let the queue
    // sort them. On top of the queue the smallest key
    for (auto& data_provider : file_providers_) {
        auto item{data_provider.read_entry()};
        if (item.has_value()) {
            queue.push(*item);
        }
    }

    // Process the queue from smallest to largest key
    while (queue.size()) {
        auto& current_item{queue.top()};                                       // Pick smallest key by reference
        auto& current_file_provider{file_providers_.at(current_item.second)};  // and set current file provider

        // Process linked pairs
        for (const auto& pair : load(current_item.first)) {
            table->put(pair.key, pair.value);
        }

        // From the provider which has served the current key
        // read next "record"
        auto next{current_file_provider.read_entry()};

        // At this point `current` has been processed.
        // We can remove it from the queue
        queue.pop();

        // Add next item to the queue only if it has
        // meaningful data
        if (next.has_value()) {
            queue.push(*next);
        } else {
            current_file_provider.reset();
        }
    }
}

std::string Collector::set_work_path(const char* provided_work_path)
{
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

std::vector<Entry> default_load(Entry entry) {
    return std::vector<Entry>({entry});
}

}  // namespace silkworm::etl
