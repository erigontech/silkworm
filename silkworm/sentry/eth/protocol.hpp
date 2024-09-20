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

#include <functional>
#include <string>
#include <utility>

#include <silkworm/sentry/rlpx/protocol.hpp>

#include "fork_id.hpp"
#include "status_data.hpp"

namespace silkworm::sentry::eth {

class Protocol : public rlpx::Protocol {
  public:
    explicit Protocol(std::function<StatusData()> status_provider)
        : status_provider_(std::move(status_provider)) {}

    ~Protocol() override = default;

    [[nodiscard]] std::pair<std::string, uint8_t> capability() override {
        return {"eth", Protocol::kVersion};
    }

    [[nodiscard]] Message first_message() override {
        auto status = status_provider_();
        return status.message.to_message();
    }

    void handle_peer_first_message(const Message& message) override;
    bool is_compatible_enr_entry(std::string_view name, ByteView data) override;

    static constexpr uint8_t kVersion{68};

  private:
    std::function<StatusData()> status_provider_;

    static bool is_compatible_fork_id(const ForkId& fork_id, const StatusData& my_status);
};

}  // namespace silkworm::sentry::eth
