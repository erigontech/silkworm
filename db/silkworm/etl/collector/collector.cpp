#include <silkworm/etl/collector/collector.hpp>
#include <silkworm/etl/dataprovider/fileProvider.hpp>
#include <silkworm/etl/heap/heap.hpp>
#include <silkworm/db/chaindb.hpp>
#include <iostream>

namespace silkworm::etl{

Collector::Collector(Buffer * _b) {
    b = _b;
    dataProviders = std::vector<FileProvider *>();
}

Collector::~Collector() {
    for (auto d: dataProviders)
    {
        d->reset();
    }
}

void Collector::flushBuffer() {
    if (b->length() == 0) {
        return;
    }

    dataProviders.push_back(new FileProvider(b, dataProviders.size()));
    b->reset();

}

void Collector::collect(silkworm::ByteView k, silkworm::ByteView v) {
    b->put(k, v);
    if (b->checkFlushSize()) {
        flushBuffer();
    }
}

/*void Collector::load(silkworm::lmdb::Table * t, OnLoad load) {
    if (dataProviders.size() == 0) {
        auto begin = b->begin();
        auto end = b->end();
        for(auto iter = begin;
            iter != end;
            ++iter ) {
            auto key = silkworm::db::to_mdb_val(iter->k);
            auto value = silkworm::db::to_mdb_val(iter->v);
            t->put_append(&key, &value);
        }
        return;
    }

    etl::Heap h = etl::new_heap();


    flushBuffer();
    for (unsigned int i = 0; i < dataProviders.size(); i++)
    {
        auto entry = dataProviders.at(i)->next();
        etl::push_heap(&h, {entry.k, entry.v, (int)i});
    }

    while (h.size() > 0) {
		auto e = etl::pop_heap(&h);
        load(e.key, e.value);
        auto key = silkworm::db::to_mdb_val(e.key);
        auto value = silkworm::db::to_mdb_val(e.value);
        t->put_append(&key, &value);
		auto next = dataProviders.at(e.time)->next();
        if (next.k.size() ==  0 && next.v.size() ==  0) {
            dataProviders.at(e.time)->reset();
            dataProviders.erase(dataProviders.begin() + e.time);
            continue;
        }
        etl::push_heap(&h, {next.k, next.v, e.time});
    }
}*/

void Collector::load(silkworm::lmdb::Table * t, silkworm::lmdb::Transaction *tx) {
    size_t s = 0;
    if (dataProviders.size() == 0) {
        b->sort();
        auto entries{b->getEntries()};
        for(auto e: *entries) {
            s += e.k.size() + e.v.size();
            t->put(e.k, e.v);
            if (s >= IDEAL_SIZE) {
                s = 0;
                silkworm::lmdb::err_handler(tx->commit());
            }
        }
        return;
    }

    auto h = etl::new_heap();
    flushBuffer();

    for (unsigned int i = 0; i < dataProviders.size(); i++)
    {
        auto entry = dataProviders.at(i)->next();
        etl::heap_elem e = {entry.k, entry.v, (int)i};
        etl::push_heap(&h, e);
    }
    while (h.size() > 0) {
		auto e{etl::pop_heap(&h)};
        s += e.key.size() + e.value.size();
        t->put(e.key, e.value);
        if (s >= IDEAL_SIZE) {
            silkworm::lmdb::err_handler(tx->commit());
        }
		auto next{dataProviders.at(e.i)->next()};
        if (next.k.size() ==  0 && next.v.size() ==  0) {
            continue;
        }
        etl::push_heap(&h, {next.k, next.v, e.i});
    }
}

}