#include <silkworm/etl/buffers/buffer.hpp>
#include <algorithm>

namespace silkworm::etl{

Buffer::Buffer(size_t _optimalSize) {
    optimalSize = _optimalSize;
    entries = std::vector<entry>();
    size = 0;
}

void Buffer::put(silkworm::ByteView k, silkworm::ByteView v) {
    size += v.size() + k.size();
    entries.push_back({k, v});
}

void Buffer::sort() {
    std::sort(entries.begin(), entries.end(), [](const entry lhs, const entry rhs) {
        return lhs.k.compare(rhs.k) < 0;
    });
}


std::vector<entry> * Buffer::getEntries() {
    return &entries;
}

int Buffer::length() {
    return entries.size();
}

void Buffer::reset() {
    entries.clear();
    entries.shrink_to_fit();
    size = 0;
}

bool Buffer::checkFlushSize() {
    return size >= optimalSize;
}

}