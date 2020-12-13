
#include <vector>
#include <string>
#include <map>
#include <algorithm>
#include <silkworm/etl/buffers/buffer.hpp>
#include <fstream>

#ifndef ETL_FILE_PROVIDER_H
#define ETL_FILE_PROVIDER_H

namespace silkworm::etl{

class FileProvider {
    public:

        FileProvider(Buffer *, int);
        entry next();
        void reset();

    private:
        std::fstream file;
        std::string filename;
};

}

#endif