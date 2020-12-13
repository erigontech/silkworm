#include <silkworm/etl/dataprovider/fileProvider.hpp>
#include <silkworm/etl/buffers/buffer.hpp>
#include <silkworm/db/chaindb.hpp>
#include <dirent.h>

#define IDEAL_SIZE 268435456

#ifndef ETL_COLLECTOR_H
#define ETL_COLLECTOR_H

namespace silkworm::etl{
typedef void (*OnLoad)(silkworm::ByteView, silkworm::ByteView);

class Collector {

    public:
        Collector(Buffer*);
        ~Collector();
        void flushBuffer();
        void collect(silkworm::ByteView k, silkworm::ByteView v);
        // void load(silkworm::lmdb::Table *, OnLoad);
        void load(silkworm::lmdb::Table *, silkworm::lmdb::Transaction *);

    private:
	    std::vector<FileProvider *> dataProviders;
        Buffer * b;
};

}
#endif