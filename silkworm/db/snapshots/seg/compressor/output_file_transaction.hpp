/*
   Copyright 2024 The Silkworm Authors

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

#pragma once

#include <filesystem>
#include <memory>
#include <ostream>

namespace silkworm::snapshots::seg {

class OutputFileTransactionImpl;

/**
 * An output file that is either fully written or deleted.
 * It opens a temporary file for writing,
 * and on commit() it fsync-s and renames it to the final file name.
 * If no commit() happens, the temporary file is deleted as if nothing has happened.
 */
class OutputFileTransaction {
  public:
    OutputFileTransaction(
        const std::filesystem::path& path,
        size_t buffer_size);
    ~OutputFileTransaction();

    void commit();

    std::ostream& stream();

  private:
    std::unique_ptr<OutputFileTransactionImpl> p_impl_;
};

}  // namespace silkworm::snapshots::seg
