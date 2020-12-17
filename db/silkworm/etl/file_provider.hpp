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
#ifndef ETL_SILKWORM_FILE_PROVIDER_H
#define ETL_SILKWORM_FILE_PROVIDER_H

#include <fstream>
#include <boost/filesystem/operations.hpp>
#include <silkworm/etl/buffer.hpp>

namespace silkworm::etl{
// FileProvider saves buffers to disk and reads from them
class FileProvider {
    public:

        FileProvider(int id);                       // Sort and write buffer to file
        void write_buffer_to_disk(Buffer *buffer);  // Write buffer to disk
        Entry next();                               // Read next element from file starting from position 0
        void reset();                               // Remove the file when eof is met

    private:
        std::fstream file_;
        std::string filename_;
};

}
#endif