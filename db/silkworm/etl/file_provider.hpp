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
#include <memory>
#include <optional>
#include <silkworm/etl/buffer.hpp>

namespace silkworm::etl {

union head_t {
    uint32_t lengths[2];
    uint8_t bytes[8];
};

// FileProvider saves buffers to disk and reads from them
class FileProvider {
  public:
    FileProvider(int id);                                    // Sort and write buffer to file
    void write_buffer_to_disk(std::vector<Entry>& entries);  // Write buffer to disk
    std::optional<Entry> read_entry();                       // Read next element from file starting from position 0
    void reset();                                            // Remove the file when eof is met

  private:
    int id_;
    std::fstream file_;
    std::string filename_;
};
}  // namespace silkworm::etl
#endif
