#include <vector>
#include <algorithm>
#include <string>
#include <silkworm/common/base.hpp>
namespace silkworm::etl {

struct heap_elem {
    silkworm::ByteView key;
    silkworm::ByteView value;
    int i;
};

typedef std::vector<heap_elem> Heap;

Heap new_heap();
heap_elem pop_heap(Heap *);
void push_heap(Heap *, heap_elem);

}