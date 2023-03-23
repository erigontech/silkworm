/*
   Copyright 2014-2015 Stanislav Ovsyannikov

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

#include <iostream>

#include "listener_cbor_log.h"

#include <evmc/evmc.hpp>
#include <silkworm/core/common/util.hpp>

namespace silkrpc {

    evmc::bytes32 to_my_bytes32(evmc::bytes32& out, silkworm::ByteView bytes) {
       if (!bytes.empty()) {
          size_t n{std::min(bytes.length(), silkworm::kHashLength)};
          std::memcpy(out.bytes + silkworm::kHashLength - n, bytes.data(), n);
       }
       return out;
    }


    void listener_cbor_log::on_bytes(unsigned char *data, int size) {
        if (state_ == WAIT_ADDRESS) {
           curr_log_.address = std::move(silkworm::to_evmc_address(silkworm::Bytes{data, (long unsigned int)size}));
           state_ = WAIT_NTOPICS;
        } else if (state_ == WAIT_TOPICS) {
           evmc::bytes32 out;
           std::memcpy(out.bytes, data, size);
           curr_log_.topics.emplace_back(std::move(out));
           if (++curr_topics_ == ntopics_) {
              state_ = WAIT_DATA;
           }
        } else if (state_ == WAIT_DATA) {
           curr_log_.data = std::move(silkworm::Bytes{data, (long unsigned int)size});
           logs_.emplace_back(std::move(curr_log_));
           curr_log_.topics.clear();
           state_ = WAIT_NFIELDS;
        } else {
           throw std::system_error{std::make_error_code(std::errc::invalid_argument), "Log CBOR: unexpected format(on_bytes bad state)"};
        }
    }

    void listener_cbor_log::on_array(int size) {
        if (state_ == WAIT_NLOGS) {
           nlogs_ = size;
           logs_.reserve(size);
           state_ = WAIT_NFIELDS;
        } else if (state_ == WAIT_NFIELDS) {
           if (size != 3) {
              throw std::system_error{std::make_error_code(std::errc::invalid_argument), "Log CBOR: unexpected format(on_array bad not 3 fields)"};
           }
           state_ = WAIT_ADDRESS;
        } else if (state_ == WAIT_NTOPICS) {
           if (size == 0) {
              state_ = WAIT_DATA;
           } else {
              curr_log_.topics.reserve(size);
              ntopics_ = size;
              curr_topics_ = 0;
              state_ = WAIT_TOPICS;
           }
        } else {
           throw std::system_error{std::make_error_code(std::errc::invalid_argument), "Log CBOR: unexpected format(on_array bad state)"};
        }
    }

    void listener_cbor_log::on_null() {
        curr_log_.data = std::move(silkworm::Bytes{});
        logs_.emplace_back(std::move(curr_log_));
        curr_log_.topics.clear();
           
        state_ = WAIT_NFIELDS;
    }

    bool listener_cbor_log::is_processing_terminated_successfully() {
       return (logs_.size()  == nlogs_);
    }
}
