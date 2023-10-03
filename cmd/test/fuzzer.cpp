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

// #define CATCH_CONFIG_MAIN

#include <string>

#include <silkworm/silkrpc/test/execution_api_database.hpp>

using namespace silkworm::rpc::test;

int doSimpleCalc(std::string& simple) {
  if (simple == "simple")
    return 1;
  else 
    return 0;
}

std::shared_ptr<mdbx::env_managed> InitializeTestBase() {
  const auto tests_dir = get_tests_dir();
  const auto db_dir = silkworm::TemporaryDirectory::get_unique_temporary_path();
  auto db = open_db(db_dir);
  silkworm::db::RWTxnManaged txn{*db};
  silkworm::db::table::check_or_create_chaindata_tables(txn);
  auto state_buffer = populate_genesis(txn, tests_dir);
  populate_blocks(txn, tests_dir, state_buffer);
  txn.commit_and_stop();

  return db;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {

  static auto db = InitializeTestBase();
  static auto request_handler = new  RpcApiTestBase<RequestHandler_ForTest>(db);

  auto request_str = std::string(reinterpret_cast<const char*>(Data), Size);
  nlohmann::json request_json;
  try {
    request_json = nlohmann::json::parse(request_str);
    if (!request_json.is_structured()) {
      return -1;
    }
  } catch (const std::exception& e) {
    return -1;
  }
  
  silkworm::rpc::http::Reply reply;
  request_handler->run<&RequestHandler_ForTest::request_and_create_reply>(request_json, reply);
  
  if (reply.status == silkworm::rpc::http::StatusType::ok) {
    return 0;
  }

  return -1;
}



