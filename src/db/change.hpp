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

#ifndef SILKWORM_DB_CHANGE_H_
#define SILKWORM_DB_CHANGE_H_

/*
Part of the compatibility layer with the Turbo-Geth DB format;
see its package changeset.
*/

#include <evmc/evmc.hpp>
#include <map>
#include <optional>
#include <string>
#include <string_view>

namespace silkworm::db {

class AccountChanges : public std::map<evmc::address, std::string> {
 public:
  // Turbo-Geth decodeAccountsWithKeyLen
  static AccountChanges decode(std::string_view encoded);

  // Turbo-Geth (AccountChangeSetPlainBytes)Find
  static std::optional<std::string_view> find(std::string_view encoded, std::string_view key);
};

class StorageChanges {
 public:
  // Turbo-Geth (StorageChangeSetPlainBytes)FindWithIncarnation
  static std::optional<std::string_view> find(std::string_view encoded, std::string_view key);
};
}  // namespace silkworm::db

#endif  // SILKWORM_DB_CHANGE_H_
