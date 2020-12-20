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

namespace silkworm::etl{
void Collector::flush_buffer() {
    buffer_.sort();
    data_providers_.emplace_back(data_providers_.size());
    data_providers_.back().write_buffer_to_disk(buffer_.get_entries());
    buffer_.reset();
}

void Collector::collect(silkworm::ByteView key, silkworm::ByteView value) {
    buffer_.put(key, value);
    if (buffer_.check_flush_size()) {
        flush_buffer();
    }
}

void Collector::load(silkworm::lmdb::Table *table, Load load) {
    if (data_providers_.size() == 0) {
        buffer_.sort();
        for(const auto& entry: buffer_.get_entries()) {
            auto pairs{load(entry.key, entry.value)};
            for (const auto& pair: pairs) table->put(pair.key, pair.value);
        }
        buffer_.reset();
        return;
    }
    flush_buffer();

    auto queue{std::priority_queue<Entry, std::vector<Entry>, std::greater<Entry>>()};

    for (auto& data_provider: data_providers_)
    {
        queue.push(data_provider.read_entry());
    }

    while (queue.size() != 0) {
        auto entry{queue.top()};
        queue.pop();
        auto pairs{load(entry.key, entry.value)};
        for (const auto& pair: pairs) table->put(pair.key, pair.value);
		auto next{data_providers_.at(entry.i).read_entry()};
        next.i = entry.i;
        if (next.key.size() == 0) {
            data_providers_.at(entry.i).reset();
            continue;
        }
        queue.push(next);
    }
}

std::vector<Entry> default_load(silkworm::ByteView key, silkworm::ByteView value) {
    return std::vector<Entry>({{key, value}});
}

}
