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

#include "index.hpp"

namespace silkworm::snapshots {

void Index::reopen_index() {
    close_index();

    index_ = std::make_unique<rec_split::RecSplitIndex>(path_.path(), region_);
}

void Index::close_index() {
    index_.reset();
}

}  // namespace silkworm::snapshots
