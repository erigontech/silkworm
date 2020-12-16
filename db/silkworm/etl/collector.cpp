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

#include <silkworm/etl/collector.hpp>


namespace silkworm::etl{
void Collector::flush_buffer() {
    data_providers_.push_back(FileProvider(buffer_, data_providers_.size()));
    buffer_->reset();
}

void Collector::collect(ByteView key, ByteView value) {
    buffer_->put(key, value);
    if (buffer_->check_flush_size()) {
        flush_buffer();
    }
}

void Collector::load(lmdb::Table *table, Load load) {
    if (data_providers_.size() == 0) {
        buffer_->sort();
        auto entries{buffer_->get_entries()};
        for(auto entry: entries) {
            auto pairs = load(entry.key, entry.value);
            for (auto pair: pairs) table->put(pair.key, pair.value);
        }
        buffer_->reset();
        return;
    }
    flush_buffer();

    auto heap = std::vector<Entry>();
    std::make_heap(heap.begin(), heap.end(), compareEntries);

    for (unsigned int i = 0; i < data_providers_.size(); i++)
    {
        auto entry = data_providers_.at(i).next();
        heap.push_back({entry.key, entry.value, (int)i});
        std::push_heap(heap.begin(), heap.end(), compareEntries);
    }

    while (heap.size() != 0) {

        std::pop_heap(heap.begin(), heap.end(), compareEntries);
        auto entry{heap.back()};
        heap.pop_back();

        auto pairs{load(entry.key, entry.value)};
        for (auto pair: pairs) table->put(pair.key, pair.value);
		auto next{data_providers_.at(entry.i).next()};
        next.i = entry.i;
        if (next.key.size() == 0) {
            data_providers_.at(entry.i).reset();
            continue;
        }
        heap.push_back(next);
        std::push_heap(heap.begin(), heap.end(), compareEntries);
    }
}

std::vector<Entry> default_load(ByteView key, ByteView value) {
    return std::vector<Entry>({{key, value, 0}});
}

}