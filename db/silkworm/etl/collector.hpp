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

#include <silkworm/etl/buffer.hpp>
#include <silkworm/etl/fileProvider.hpp>
#include <silkworm/db/chaindb.hpp>

#ifndef SILKWORM_ETL_COLLECTOR_H
#define SILKWORM_ETL_COLLECTOR_H

namespace silkworm::etl{

constexpr size_t optimal_buffer_size = 268435456;
constexpr size_t ideal_batch_size = 134217728; // TODO: Commit after ideal size is reached and open new transaction
// After collection further processing can be made to key-value pairs.
// Returned vector of entries will be inserted afterwards.
typedef std::vector<Entry> (*Load)(ByteView, ByteView);
// Collector collects entries that needs to be sorted and load them in the table in sorted order
class Collector {

    public:
        Collector(Buffer * buffer): buffer_(buffer) {};
        // Write buffer to file
        void flush_buffer();
        // Store key-value pair in memory or on disk
        void collect(ByteView key, ByteView value);
        // Load collected entries in destination table
        void load(lmdb::Table * table, Load load);

    private:
	    std::vector<FileProvider> data_providers_;
        Buffer * buffer_;
};
// Load function for no processing
std::vector<Entry> default_load(ByteView key, ByteView value);

}
#endif