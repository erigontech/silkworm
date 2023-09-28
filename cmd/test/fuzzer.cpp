#include <string>
#include <stdio.h>
#include <cstring>
#include <string>
#include <vector>
#include <sstream>
#include <functional>
#include <map>


#include <bit>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <utility>
#include <vector>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/thread_pool.hpp>
#include <catch2/catch.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/core/chain/genesis.hpp>
#include <silkworm/core/execution/address.hpp>
#include <silkworm/core/execution/execution.hpp>
#include <silkworm/core/state/in_memory_state.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/receipt.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/node/db/access_layer.hpp>
#include <silkworm/node/db/buffer.hpp>
#include <silkworm/silkrpc/common/constants.hpp>
#include <silkworm/silkrpc/ethdb/file/local_database.hpp>
#include <silkworm/silkrpc/http/request_handler.hpp>
#include <silkworm/silkrpc/test/context_test_base.hpp>


std::vector<std::string> split(const std::string& s, char delimiter) {
   std::vector<std::string> tokens;
   std::string token;
   std::istringstream tokenStream(s);
   while (std::getline(tokenStream, token, delimiter)) {
      tokens.push_back(token);
   }
   return tokens;
}

int plus(int a, int b) {
  return a + b;
}

int end(int a, int b) {
  return a + b;
}

int minus(int a, int b) {
  return a - b;
}

std::map<std::string, std::function<int(int, int)>> kOperators = {
  {"+", plus},
  {"-", minus},
  {".", end},
};

int doSimpleCalc(std::string& simple) {
  int result = 0;

  auto tokens = split(simple, ' ');
  if (tokens.size() < 2) {
    // Nothing todo.
    return 0;
  }

  if (tokens[0] != "doSimpleCalc:") {
    // Nothing todo.
    return 0;
  }

  auto& ops = kOperators;
  for (size_t i = 2; i < tokens.size(); i++) {
    if (i % 2 == 0) {
      int n = 0;
      try {
        // TODO[1]: Uncomment this line.
        //n = std::stoi(tokens[i-1], nullptr, 0);

        // TODO[2]: Uncomment this line.
        //result = ops[tokens[i]](result, n);
      } catch (...) {
        // Let all exceptions pass through.
      }
      
      // TODO[1]: Erase this line.
      n = std::stoi(tokens[i-1], nullptr, 0);

      // TODO[2]: Erase this line.
      result = ops[tokens[i]](result, n);
    }
  }

  return result;
}

void printSimpleYay(int n) {
  char* yay = nullptr;

  if (static_cast<size_t>(n*3) > static_cast<size_t>(4096)) {
    // Too large, not so yay.

    // TODO[4]: Uncomment this line.
    // return;
  }


  yay = static_cast<char*>(malloc((static_cast<size_t>(n)*3u<4096u) ? static_cast<size_t>(n)*3u : 4096u));

  std::string oneyay{"yay"};
  for (size_t i = 0u; i < static_cast<size_t>(n); i++) {
    memcpy(yay, oneyay.data(), oneyay.size());
  }

  printf("%s", yay);

  // TODO[3]: Make sure to keep memory sane.
  // free(yay);
}


extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
  std::string k(reinterpret_cast<const char*>(Data), Size);
  auto n = doSimpleCalc(k);

  if (n == 103) {
    printSimpleYay(n);
  }
  return 0;
}



