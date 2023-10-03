#include "fuzzer.cpp"

int main() {
    auto str = R"({"jsonrpc":"2.0","id":1,"method":"eth_getTransactionByHash","params":["0x54b25c11650dca0253ef7b91b5415680eea8dac54b029863e12db48908ad386c"]})";
    auto data = reinterpret_cast<const uint8_t*>(str);
    auto size = strlen(str);
    return LLVMFuzzerTestOneInput(data, size);
}
