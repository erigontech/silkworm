/*
Copyright 2021-2022 The Silkworm Authors

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

#ifndef SILKWORM_BODY_PERSISTENCE_H
#define SILKWORM_BODY_PERSISTENCE_H

#include "db_tx.hpp"
#include "types.hpp"

namespace silkworm {

class BodyPersistence {
  public:
    BodyPersistence(Db::ReadWriteAccess::Tx&);

    void persist(const BlockBody&);
    void persist(const std::vector<BlockBody>&);
    void close();

    bool unwind_needed() const;

    BlockNum unwind_point() const;
    BlockNum initial_height() const;
    BlockNum highest_height() const;
  private:
    [[maybe_unused]] Db::ReadWriteAccess::Tx& tx_;
};

}

#endif  // SILKWORM_BODY_PERSISTENCE_H
