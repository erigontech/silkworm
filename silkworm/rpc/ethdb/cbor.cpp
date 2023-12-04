/*
   Copyright 2023 The Silkworm Authors

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

#include "cbor.hpp"

#include <algorithm>
#include <utility>
#include <vector>

#include <cbor/cbor.h>
#include <cbor/listener.h>
#include <nlohmann/json.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/json/types.hpp>

namespace silkworm::rpc {

class LogCborListener : public cbor::listener {
  private:
    enum class ProcessingState {
        kWaitNLogs,
        kWaitNFields,
        kWaitAddress,
        kWaitNTopics,
        kWaitTopics,
        kWaitData
    };

  public:
    explicit LogCborListener(std::vector<Log>& logs)
        : state_(ProcessingState::kWaitNLogs), logs_(logs), current_log_{} {}

    void on_integer(int) override {
        throw std::invalid_argument("Log CBOR: unexpected format(on_integer)");
    }

    void on_map(int) override {
        throw std::invalid_argument("Log CBOR: unexpected format(on_map)");
    }

    void on_string(std::string&) override {
        throw std::invalid_argument("Log CBOR: unexpected format(on_string)");
    }

    void on_tag(unsigned int) override {
        throw std::invalid_argument("Log CBOR: unexpected format(on_tag)");
    }

    void on_undefined() override {
        throw std::invalid_argument("Log CBOR: unexpected format(on_undefined)");
    }

    void on_extra_integer(unsigned long long, int) override {
        throw std::invalid_argument("Log CBOR: unexpected format(on_extra_integer)");
    }

    void on_bool(bool) override {
        throw std::invalid_argument("Log CBOR: unexpected format(on_bool)");
    }

    void on_extra_tag(unsigned long long) override {
        throw std::invalid_argument("Log CBOR: unexpected format(on_extra_tag)");
    }

    void on_float32(float) override {
        throw std::invalid_argument("Log CBOR: unexpected format(on_float)");
    }

    void on_double(double) override {
        throw std::invalid_argument("Log CBOR: unexpected format(on_double)");
    }

    void on_extra_special(unsigned long long) override {
        throw std::invalid_argument("Log CBOR: unexpected format(on_extra_special)");
    }

    void on_error(const char*) override {
        throw std::invalid_argument("Log CBOR: unexpected format(on_error)");
    }

    void on_special(unsigned int) override {
        throw std::invalid_argument("Log CBOR: unexpected format(on_special)");
    }

    void on_bytes(unsigned char* data, int size) override {
        if (size < 0) {
            throw std::invalid_argument("Log CBOR: unexpected format(on_bytes negatize size)");
        }
        if (state_ == ProcessingState::kWaitAddress) {
            size_t n{static_cast<size_t>(size) < kAddressLength ? static_cast<size_t>(size) : kAddressLength};
            std::memcpy(current_log_.address.bytes + kAddressLength - n, data, n);
            state_ = ProcessingState::kWaitNTopics;
        } else if (state_ == ProcessingState::kWaitTopics) {
            evmc::bytes32 out;
            std::memcpy(out.bytes, data, static_cast<size_t>(size));
            current_log_.topics.emplace_back(out);
            if (++current_topic_ == num_topics_) {
                state_ = ProcessingState::kWaitData;
            }
        } else if (state_ == ProcessingState::kWaitData) {
            current_log_.data.resize(static_cast<std::vector<evmc::bytes32>::size_type>(size));
            std::memcpy(current_log_.data.data(), data, static_cast<size_t>(size));
            logs_.emplace_back(std::move(current_log_));
            current_log_.topics.clear();
            state_ = ProcessingState::kWaitNFields;
        } else {
            throw std::invalid_argument("Log CBOR: unexpected format(on_bytes bad state)");
        }
    }

    void on_array(int size) override {
        if (size < 0) {
            throw std::invalid_argument("Log CBOR: unexpected format(on_array negatize size)");
        }
        if (state_ == ProcessingState::kWaitNLogs) {
            num_logs_ = size;
            logs_.reserve(static_cast<std::vector<evmc::bytes32>::size_type>(size));
            state_ = ProcessingState::kWaitNFields;
        } else if (state_ == ProcessingState::kWaitNFields) {
            if (size != 3) {
                throw std::invalid_argument("Log CBOR: unexpected format(on_array wrong number of fields)");
            }
            state_ = ProcessingState::kWaitAddress;
        } else if (state_ == ProcessingState::kWaitNTopics) {
            if (size == 0) {
                state_ = ProcessingState::kWaitData;
            } else {
                current_log_.topics.reserve(static_cast<std::vector<evmc::bytes32>::size_type>(size));
                num_topics_ = size;
                current_topic_ = 0;
                state_ = ProcessingState::kWaitTopics;
            }
        } else {
            throw std::invalid_argument("Log CBOR: unexpected format(on_array bad state)");
        }
    }

    void on_null() override {
        current_log_.data = silkworm::Bytes{};
        logs_.emplace_back(std::move(current_log_));
        current_log_.topics.clear();
        state_ = ProcessingState::kWaitNFields;
    }

    bool success() {
        return std::cmp_equal(logs_.size(), num_logs_);
    }

  private:
    ProcessingState state_;
    int num_logs_{0};
    int num_topics_{0};
    std::vector<Log>& logs_;

    Log current_log_;
    int current_topic_{0};
};

bool cbor_decode(const silkworm::Bytes& bytes, std::vector<Log>& logs) {
    if (bytes.empty()) {
        return false;
    }
    const void* data = static_cast<const void*>(bytes.data());
    cbor::input input(const_cast<void*>(data), static_cast<int>(bytes.size()));
    LogCborListener listener(logs);
    cbor::decoder decoder(input, listener);
    decoder.run();
    const auto decode_success = listener.success();
    if (!decode_success) {
        SILK_ERROR << "cbor_decode<std::vector<Log>> unexpected cbor: wrong number of logs";
    }
    return decode_success;
}

bool cbor_decode(const silkworm::Bytes& bytes, std::vector<Receipt>& receipts) {
    if (bytes.empty()) {
        return false;
    }
    auto json = nlohmann::json::from_cbor(bytes);
    SILK_TRACE << "cbor_decode<std::vector<Receipt>> json: " << json.dump();
    if (json.is_array()) {
        receipts = json.get<std::vector<Receipt>>();
        return true;
    } else if (json.is_null()) {
        return true;
    } else {
        SILK_ERROR << "cbor_decode<std::vector<Receipt>> unexpected json: " << json.dump();
        return false;
    }
}

}  // namespace silkworm::rpc
