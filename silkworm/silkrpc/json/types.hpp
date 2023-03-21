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

#pragma once

#include <optional>
#include <set>
#include <string>
#include <vector>

#include <intx/intx.hpp>
#include <evmc/evmc.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/silkrpc/types/block.hpp>
#include <silkworm/silkrpc/types/call.hpp>
#include <silkworm/silkrpc/types/chain_config.hpp>
#include <silkworm/silkrpc/types/chain_traffic.hpp>
#include <silkworm/silkrpc/types/error.hpp>
#include <silkworm/silkrpc/types/execution_payload.hpp>
#include <silkworm/silkrpc/types/filter.hpp>
#include <silkworm/silkrpc/types/issuance.hpp>
#include <silkworm/silkrpc/types/log.hpp>
#include <silkworm/silkrpc/types/node_info.hpp>
#include <silkworm/silkrpc/types/syncing_data.hpp>
#include <silkworm/silkrpc/types/receipt.hpp>
#include <silkworm/silkrpc/types/transaction.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/transaction.hpp>

namespace evmc {

void to_json(nlohmann::json& json, const address& addr);
void from_json(const nlohmann::json& json, address& addr);

void to_json(nlohmann::json& json, const bytes32& b32);
void from_json(const nlohmann::json& json, bytes32& b32);

} // namespace evmc

namespace intx {

void from_json(const nlohmann::json& json, uint256& ui256);

} // namespace intx

namespace silkworm {

void to_json(nlohmann::json& json, const BlockHeader& ommer);

void to_json(nlohmann::json& json, const Transaction& transaction);

void from_json(const nlohmann::json& json, AccessListEntry& entry);

} // namespace silkworm

namespace silkrpc {

void to_json(nlohmann::json& json, const struct NodeInfo& node_info);

void to_json(nlohmann::json& json, const struct NodeInfoPorts& node_info_ports);

void to_json(nlohmann::json& json, const struct ChainTraffic& chain_traffic);

void to_json(nlohmann::json& json, const struct TxPoolStatusInfo& status_info);

void to_json(nlohmann::json& json, const AccessListResult& access_list_result);

void to_json(nlohmann::json& json, const struct CallBundleTxInfo& tx_info);

void to_json(nlohmann::json& json, const struct CallBundleInfo& bundle_info);

void to_json(nlohmann::json& json, const SyncingData& syncing_data);

void to_json(nlohmann::json& json, const StageData& stage_data);

void to_json(nlohmann::json& json, const Rlp& rlp);

void to_json(nlohmann::json& json, const Block& b);

void to_json(nlohmann::json& json, const Transaction& transaction);

void from_json(const nlohmann::json& json, Call& call);

void to_json(nlohmann::json& json, const Log& log);
void from_json(const nlohmann::json& json, Log& log);

void to_json(nlohmann::json& json, const Receipt& receipt);
void from_json(const nlohmann::json& json, Receipt& receipt);

void to_json(nlohmann::json& json, const Filter& filter);
void from_json(const nlohmann::json& json, Filter& filter);

void to_json(nlohmann::json& json, const ExecutionPayload& execution_payload);
void from_json(const nlohmann::json& json, ExecutionPayload& execution_payload);

void to_json(nlohmann::json& json, const ForkChoiceState& forkchoice_state);
void from_json(const nlohmann::json& json, ForkChoiceState& forkchoice_state);

void to_json(nlohmann::json& json, const PayloadAttributes& payload_attributes);
void from_json(const nlohmann::json& json, PayloadAttributes& payload_attributes);

void to_json(nlohmann::json& json, const ForkChoiceUpdatedReply& forkchoice_updated_reply);

void to_json(nlohmann::json& json, const PayloadStatus& payload_status);

void to_json(nlohmann::json& json, const TransitionConfiguration& transition_configuration);
void from_json(const nlohmann::json& json, TransitionConfiguration& transition_configuration);

void to_json(nlohmann::json& json, const Forks& forks);

void to_json(nlohmann::json& json, const Issuance& issuance);

void to_json(nlohmann::json& json, const Error& error);
void to_json(nlohmann::json& json, const RevertError& error);

void to_json(nlohmann::json& json, const std::set<evmc::address>& addresses);

std::string to_hex_no_leading_zeros(uint64_t number);
std::string to_hex_no_leading_zeros(silkworm::ByteView bytes);

std::string to_quantity(uint64_t number);
std::string to_quantity(intx::uint256 number);
std::string to_quantity(silkworm::ByteView bytes);


struct json_buffer {

  json_buffer(json_buffer&& o) : buffer_(o.buffer_), curr_(o.curr_) {
  }

  json_buffer(char *buffer, int max_len) : buffer_(buffer), curr_(buffer), max_len_(max_len) {
     *curr_++ = '{'; 
  }

  inline void set_data(const char *data, int len) {
       std::memcpy (buffer_, data, len);
       curr_+=len; 
  }

  inline void set_curr(char *curr) {
     curr_=curr;
  }

  inline void reset() {
      curr_ = &buffer_[1];
      first_element = 1;
      first_attribute = 1;
  }

  inline void end() {
     *curr_++ = '}'; 
  }

  inline void add_attribute_name(const char *name, int len) {
    auto ptr = curr_;
    if (first_attribute) { 
       first_attribute = 0; 
    } 
    else { \
       *ptr++ = ','; 
    }
    *ptr++ = '\"'; 
    memcpy(ptr, name, len); 
    ptr+=len;
    *ptr++ = '\"'; 
    *ptr++ = ':'; 
    *ptr++ = '\"'; \
    curr_ = ptr;
  }

  inline void add_attribute_name_list(const char *name, int len) {
    auto ptr = curr_;
    if (first_attribute) { 
       first_attribute = 0; 
    } 
    else { \
       *ptr++ = ','; 
    }
    *ptr++ = '\"'; 
    memcpy(ptr, name, len); 
    ptr+=len;
    *ptr++ = '\"'; 
    *ptr++ = ':'; 
    *ptr++ = '['; 
    curr_ = ptr;
    first_attribute = 1;
  }

  // XXX
  inline void add_attribute_name2(const char *name, int len) {
    auto ptr = curr_;
    if (first_attribute) { 
       first_attribute = 0; 
    } 
    else { \
       *ptr++ = ','; 
    }
    *ptr++ = '\"'; 
    memcpy(ptr, name, len); 
    ptr+=len;
    *ptr++ = '\"'; 
    *ptr++ = ':'; 
    curr_ = ptr;
  }

  inline char *get_addr() {
    return curr_;
  }

  void dump() {
     int len = curr_-buffer_;
     printf ("BufferLen: %d\n",len);
     for (auto i = 0; i < len; i++) {
        printf ("%x ",buffer_[i]);
     }
  }

  inline void add_attribute_value(int len) {
       curr_+=len; 
       *curr_++ = '\"'; 
  }

  // XXX
  inline void add_attribute_value2(int len) {
       curr_+=len; 
  }

  inline void start_object(const char *name, int len) {
    auto ptr = curr_;
    if (first_attribute) {
       first_attribute = 0;
    }
    else { \
       *ptr++ = ',';
    }
    *ptr++ = '\"';
    memcpy(ptr, name, len);
    ptr+=len;
    *ptr++ = '\"';
    *ptr++ = ':';
    *ptr++ = '{';
    curr_ = ptr;
    first_attribute = 1;
  }

  inline void end_object() {
     *curr_++ = '}';
  }


  inline void add_attribute_value(const char *value) {
       int len = strlen(value);
       memcpy(curr_, value, len); 
       curr_+=len; 
       *curr_++ = '\"'; 
  }

  inline void add_attribute_value_list(const char *value, int len) {
       auto ptr = curr_;
       if (first_attribute) {
          first_attribute = 0;
       }
       else { \
          *ptr++ = ',';
       }
       *ptr++ = '\"';
       memcpy(ptr, value, len);
       ptr+=len;
       *ptr++ = '\"';
       curr_ = ptr;
  }


  inline void start_vector(const char *name, int len) {
       auto ptr = curr_;
       *ptr++ = ','; 
       *ptr++ = '\"'; 
       memcpy(ptr, name, len); 
       ptr+=len;
       *ptr++ = '\"'; 
       *ptr++ = ':'; 
       *ptr++ = '[';
       first_element = 1; 
       curr_ = ptr;
  }

  inline void end_vector() {
       *curr_++ = ']';
  }

  inline void start_vector_element() {
       if (first_element) { 
          first_element = 0; 
       } 
       else 
          *curr_++ = ','; 
       *curr_++ = '{'; 
       first_attribute = 1; 
  }

  inline void end_vector_element() {
       *curr_++ = '}';
  }

  inline void add_end_attribute_list() {
     *curr_++ = ']';
  }

  std::string_view to_string_view() { 
       //std::cout << "\n to_string_view::Message-Len: " << (int)(curr_ - buffer_ - 1) << "\n"; 
       return std::string_view(buffer_, curr_ - buffer_ - 1 );
  }

  char *buffer_;
  char *curr_;
  int max_len_;
  int first_element = 1; 
  int first_attribute = 1; 
};

void make_json_error(json_buffer& out, uint32_t id, int32_t code, const std::string& message);
void make_json_content(json_buffer& out, uint32_t id, const silkrpc::Logs& logs);

nlohmann::json make_json_content(uint32_t id);
nlohmann::json make_json_content(uint32_t id, const nlohmann::json& result);

void make_json_content2(json_buffer& out, uint32_t id, const silkrpc::Logs& logs);

void make_json_content4(std::string& out, uint32_t id, const silkrpc::Logs& logs);
void make_json_error(std::string& buffer, uint32_t id, int32_t code, const std::string& message);

nlohmann::json make_json_error(uint32_t id, int32_t code, const std::string& message);
nlohmann::json make_json_error(uint32_t id, const RevertError& error);

} // namespace silkrpc

namespace nlohmann {

template <>
struct adl_serializer<silkrpc::BlockNumberOrHash> {
    static silkrpc::BlockNumberOrHash from_json(const json& json) {
        if (json.is_string()) {
            return silkrpc::BlockNumberOrHash{json.get<std::string>()};
        } else if (json.is_number()) {
            return silkrpc::BlockNumberOrHash{json.get<std::uint64_t>()};
        }
        return silkrpc::BlockNumberOrHash{0};
    }
};

} // namespace nlohmann

