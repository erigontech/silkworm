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

#include <vector>

#include <cbor/cbor.h>
#include <cbor/listener.h>

#include <nlohmann/json.hpp>

#include <silkworm/silkrpc/common/log.hpp>
#include <silkworm/silkrpc/common/util.hpp>
#include <silkworm/silkrpc/json/types.hpp>

namespace silkrpc {

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
    LogCborListener(std::vector<Log>& logs): state_(ProcessingState::kWaitNLogs), nlogs_(0), ntopics_(0), logs_(logs), current_log_({}), current_topic_(0) {}

    void on_integer(int ) { 
        throw std::invalid_argument("Log CBOR: unexpected format(on_integer)");
    }

    void on_map(int ) { 
        throw std::invalid_argument("Log CBOR: unexpected format(on_map)");
    }
        
    void on_string(std::string &) { 
        throw std::invalid_argument("Log CBOR: unexpected format(on_string)");
    }

    void on_tag(unsigned int) { 
        throw std::invalid_argument("Log CBOR: unexpected format(on_tag)");
    }

    void on_undefined() { 
        throw std::invalid_argument("Log CBOR: unexpected format(on_undefined)");
    }

    void on_extra_integer(unsigned long long , int ) { 
        throw std::invalid_argument("Log CBOR: unexpected format(on_extra_integer)");
    }

    void on_bool(bool ) { 
        throw std::invalid_argument("Log CBOR: unexpected format(on_bool)");
    }

    void on_extra_tag(unsigned long long ) { 
        throw std::invalid_argument("Log CBOR: unexpected format(on_extra_tag)");
    }

    void on_float32(float ) { 
        throw std::invalid_argument("Log CBOR: unexpected format(on_float)");
    }

    void on_double(double ) { 
        throw std::invalid_argument("Log CBOR: unexpected format(on_double)");
    }

    void on_extra_special(unsigned long long ) { 
        throw std::invalid_argument("Log CBOR: unexpected format(on_extra_special)");
    }

    void on_error(const char *) { 
        throw std::invalid_argument("Log CBOR: unexpected format(on_error)");
    }

    void on_special(unsigned int) { 
        throw std::invalid_argument("Log CBOR: unexpected format(on_special)");
    }

    void on_bytes(unsigned char *data, int size) {
        if (state_ == ProcessingState::kWaitAddress) {
            current_log_.address = silkworm::to_evmc_address(silkworm::Bytes{data, static_cast<long unsigned int>(size)});
            state_ = ProcessingState::kWaitNTopics;
        } else if (state_ == ProcessingState::kWaitTopics) {
            evmc::bytes32 out;
            std::memcpy(out.bytes, data, static_cast<size_t>(size));
            current_log_.topics.emplace_back(std::move(out));
            if (++current_topic_ == ntopics_) {
                state_ = ProcessingState::kWaitData;
            }
        } else if (state_ == ProcessingState::kWaitData) {
            current_log_.data = silkworm::Bytes{data, static_cast<long unsigned int>(size)};
            logs_.emplace_back(std::move(current_log_));
            current_log_.topics.clear();
            state_ = ProcessingState::kWaitNFields;
        } else {
            throw std::invalid_argument("Log CBOR: unexpected format(on_bytes bad state)");
        }
    }

    void on_array(int size) {
        if (state_ == ProcessingState::kWaitNLogs) {
            nlogs_ = size;
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
                ntopics_ = size;
                current_topic_ = 0;
                state_ = ProcessingState::kWaitTopics;
            }
        } else {
            throw std::invalid_argument("Log CBOR: unexpected format(on_array bad state)");
        }
    }
    
    void on_null() {
        current_log_.data = silkworm::Bytes{};
        logs_.emplace_back(std::move(current_log_));
        current_log_.topics.clear();
        state_ = ProcessingState::kWaitNFields;
    }

    bool success() {
       if (static_cast<int>(logs_.size())  != nlogs_) {
           throw std::invalid_argument("Log CBOR: wrong number of logs");
       }
       return true;
    }

  private:
        ProcessingState state_;
        int nlogs_;
        int ntopics_;
        std::vector<Log>& logs_;

        Log current_log_;
        int current_topic_;
};


bool cbor_decode(const silkworm::Bytes& bytes, std::vector<Log>& logs) {
    if (bytes.size() == 0) {
        return false;
    }
    const void* data = static_cast<const void*>(bytes.data());
    cbor::input input(const_cast<void*>(data), bytes.size());
    LogCborListener listener(logs);
    cbor::decoder decoder(input, listener);
    decoder.run();
    if (!listener.success()) {
        SILKRPC_ERROR << "cbor_decode<std::vector<Log>> unexpected cbor" << "\n";
        return false;
    }
    return true;
}

bool cbor_decode(const silkworm::Bytes& bytes, std::vector<Receipt>& receipts) {
    if (bytes.size() == 0) {
        return false;
    }
    auto json = nlohmann::json::from_cbor(bytes);
    SILKRPC_TRACE << "cbor_decode<std::vector<Receipt>> json: " << json.dump() << "\n";
    if (json.is_array()) {
        receipts = json.get<std::vector<Receipt>>();
        return true;
    } else {
        SILKRPC_ERROR << "cbor_decode<std::vector<Receipt>> unexpected json: " << json.dump() << "\n";
        return false;
    }
}

}  // namespace silkrpc
