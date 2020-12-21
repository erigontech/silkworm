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
#include <silkworm/etl/util.hpp>

namespace silkworm::etl {

/**
 * Provides an abstraction to flush data to disk
 * and re-read flushed data sequentially
 */
class FileProvider {
  public:
    FileProvider(const std::string& working_path, size_t id);
    void flush(Buffer& buffer);                         // Write buffer's contents to disk
    std::optional<std::pair<Entry, int>> read_entry();  // Read next data element from file starting from position 0
    void reset();                                       // Remove the file when eof is met

  private:
    size_t id_;
    std::fstream file_;
    std::string filename_;
};
}  // namespace silkworm::etl
#endif
