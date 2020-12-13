#include <silkworm/etl/heap/heap.hpp>

namespace silkworm::etl {

Heap new_heap() {
    auto h{Heap()};
    std::make_heap(h.begin(), h.end(), [](const heap_elem lhs, const heap_elem rhs) {
        return lhs.key.compare(rhs.key) > 0;
    });
    return h;
}

heap_elem pop_heap(Heap *h) {
    std::pop_heap (h->begin(), h->end(), [](const heap_elem lhs, const heap_elem rhs) {
        return lhs.key.compare(rhs.key) > 0;
    });
    auto top{h->back()};
    h->pop_back();
    return top;
}

void push_heap(Heap *h, heap_elem e) {
    h->push_back(e);
    std::push_heap(h->begin(), h->end(), [](const heap_elem lhs, const heap_elem rhs) {
        return lhs.key.compare(rhs.key) > 0;
    });
}

}