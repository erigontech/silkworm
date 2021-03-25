/*
   Copyright 2020-2021 The Silkworm Authors

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

#ifndef ETL_SILKWORM_FILE_PROVIDER_HPP_
#define ETL_SILKWORM_FILE_PROVIDER_HPP_

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
    FileProvider(std::string file_name, size_t id);
    ~FileProvider(void);
    void flush(Buffer& buffer);                         // Write buffer's contents to disk
    std::optional<std::pair<Entry, int>> read_entry();  // Read next data element from file starting from position 0
    void reset();                                       // Remove the file when eof is met

    std::string get_file_name(void) const;
    size_t get_file_size(void) const;

  private:
    size_t id_;
    std::fstream file_;      // Actual file stream
    std::string file_name_;  // Actual name of file
    size_t file_size_{0};    // Actual size of written data
};

}  // namespace silkworm::etl

#endif  // !ETL_SILKWORM_FILE_PROVIDER_HPP_
