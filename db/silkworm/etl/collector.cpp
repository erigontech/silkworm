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
#include <silkworm/etl/fileProvider.hpp>
#include <iostream>

namespace silkworm::etl{
Collector::Collector(Buffer * _buffer) {
    buffer = _buffer;
    data_providers = std::vector<FileProvider>();
}

void Collector::flush_buffer() {
    if (buffer->length() == 0) {
        return;
    }

    data_providers.push_back(FileProvider(buffer, data_providers.size()));
    buffer->reset();
}

void Collector::collect(ByteView key, ByteView value) {
    buffer->put(key, value);
    if (buffer->check_flush_size()) {
        flush_buffer();
    }
}

void Collector::load(lmdb::Table *table, lmdb::Transaction *transaction, Load load) {
    size_t batch_size = 0;
    if (data_providers.size() == 0) {
        buffer->sort();
        auto entries{buffer->get_entries()};
        for(auto entry: entries) {
            batch_size += entry.key.size() + entry.value.size();

            auto pairs = load(entry.key, entry.value);
            for (auto pair: pairs) table->put(pair.key, pair.value);

            if (batch_size >= ideal_size) {
                batch_size = 0;
                lmdb::err_handler(transaction->commit());
            }
        }
        return;
    }
    flush_buffer();

    auto heap = std::vector<etl_entry>();
    std::make_heap(heap.begin(), heap.end(), compareEntries);

    for (unsigned int i = 0; i < data_providers.size(); i++)
    {
        auto entry = data_providers.at(i).next();
        heap.push_back({entry.key, entry.value, (int)i});
        std::push_heap(heap.begin(), heap.end(), compareEntries);
    }

    while (heap.size() > 0) {

        std::pop_heap(heap.begin(), heap.end(), compareEntries);
        auto entry{heap.back()};
        heap.pop_back();

        batch_size += entry.key.size() + entry.value.size();

        auto pairs = load(entry.key, entry.value);
        for (auto pair: pairs) table->put(pair.key, pair.value);

        if (batch_size >= ideal_size) {
            lmdb::err_handler(transaction->commit());
        }

		auto next{data_providers.at(entry.i).next()};
        if (next.key.size() ==  0 && next.value.size() ==  0) {
            data_providers.at(entry.i).reset();
            continue;
        }
        heap.push_back(next);
        std::push_heap(heap.begin(), heap.end(), compareEntries);
    }
}

std::vector<etl_entry> default_load(ByteView key, ByteView value) {
    return std::vector<etl_entry>({{key, value, 0}});
}

}