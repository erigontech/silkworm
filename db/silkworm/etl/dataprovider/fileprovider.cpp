#include <silkworm/etl/dataprovider/fileProvider.hpp>
#include <boost/endian/conversion.hpp>
#include <silkworm/common/util.hpp>
#include <string.h>
#include <cstdio>
#include <stdlib.h>
#include <sys/stat.h>
#include <iostream>

namespace silkworm::etl{

std::string byteviewToString(silkworm::ByteView bytes) {
    auto res{std::string()};
    for (unsigned int i = 0; i < bytes.size(); i++) {
        res.push_back((char) bytes.at(i));
    }
    return res;

}

FileProvider::FileProvider(Buffer * b, int i) {
    file.open("tmp" + std::to_string(i), std::ios_base::in | std::ios_base::out | std::ios_base::trunc);
    filename = "tmp" + std::to_string(i);
    b->sort();
    auto entries{b->getEntries()};
    for(auto e: *entries) {
        auto k{e.k};
        auto v{e.v};
        auto flow{std::string()};
        flow.push_back((char) k.size());
        flow.push_back((char) v.size());
        flow.append(byteviewToString(k));
        flow.append(byteviewToString(v));
        file << flow;
    }
    file.seekp(0);
}

entry FileProvider::next() {
    if (file.eof()) {
        return {silkworm::ByteView(), silkworm::ByteView()};
    }
    char readLength[2];
    file.read(readLength, 2);
    auto kLength{(int) readLength[0]};
    auto vLength{(int) readLength[1]};
    auto k{new unsigned char[kLength]};
    auto v{new unsigned char[vLength]};

    file.read((char *)k, kLength);
    file.read((char *)v, vLength);

    return {silkworm::ByteView(k, kLength), silkworm::ByteView(v, vLength)};
}

void FileProvider::reset() {
    std::remove(filename.c_str());
}

}