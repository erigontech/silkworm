/*
Copyright 2022 The Silkworm Authors

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

#include "silkworm/common/log.hpp"
#include "silkworm/common/settings.hpp"
#include "silkworm/concurrency/stoppable.hpp"
#include "silkworm/db/stages.hpp"
#include "silkworm/db/tables.hpp"
#include "silkworm/downloader/internals/types.hpp"

namespace silkworm::chainsync {

class Stage : public Stoppable {
  public:
    explicit Stage(std::string name);
    virtual ~Stage() = default;

    struct NewHeight {BlockNum block_num; Hash hash;};
    struct UnwindPoint {BlockNum block_num; Hash hash; std::optional<Hash> bad_block;};

    virtual NewHeight forward(std::optional<NewHeight>) = 0;
    virtual void unwind(UnwindPoint) = 0;

    virtual std::vector<std::string> get_log_progress() = 0;

  protected:
    std::string name_;
};

}  // namespace silkworm::chainsync
