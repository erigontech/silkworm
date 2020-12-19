#ifndef SILKWORM_ETL_ERROR_H
#define SILKWORM_ETL_ERROR_H


#include <stdexcept>

namespace silkworm::etl{

class ETLError : public std::runtime_error {
  public:
    using std::runtime_error::runtime_error;
};

}
#endif