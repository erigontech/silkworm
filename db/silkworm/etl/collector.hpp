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

#include <silkworm/etl/fileProvider.hpp>
#include <silkworm/etl/buffer.hpp>
#include <silkworm/db/chaindb.hpp>
#include <dirent.h>

namespace silkworm::etl{

const size_t optimal_buffer_size = 268435456;
const size_t ideal_size = 134217728;
// After collection further processing can be made to key-value pairs.
// Returned vector of entries will be inserted afterwards.
typedef std::vector<etl_entry> (*Load)(ByteView, ByteView);
// Collector collects entries that needs to be sorted and load them in the table in sorted order
class Collector {

    public:
        Collector(Buffer * _buffer);
        // Write buffer to file
        void flush_buffer();
        // Store key-value pair in memory or on disk
        void collect(ByteView key, ByteView value);
        // Load collected entries in destination table
        void load(lmdb::Table * table, lmdb::Transaction *transaction, Load load);

    private:
	    std::vector<FileProvider> data_providers;
        Buffer * buffer;
};
// Load function for no processing
std::vector<etl_entry> default_load(ByteView key, ByteView value);

}