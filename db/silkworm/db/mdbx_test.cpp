/*
   Copyright 2021 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include "mdbx.hpp"

#include <map>

#include <catch2/catch.hpp>

#include <silkworm/common/temp_dir.hpp>

static const std::map<std::string, std::string> kGeneticCode{
    {"AAA", "Lysine"},        {"AAC", "Asparagine"},    {"AAG", "Lysine"},        {"AAU", "Asparagine"},
    {"ACA", "Threonine"},     {"ACC", "Threonine"},     {"ACG", "Threonine"},     {"ACU", "Threonine"},
    {"AGA", "Arginine"},      {"AGC", "Serine"},        {"AGG", "Arginine"},      {"AGU", "Serine"},
    {"AUA", "Isoleucine"},    {"AUC", "Isoleucine"},    {"AUG", "Methionine"},    {"AUU", "Isoleucine"},
    {"CAA", "Glutamine"},     {"CAC", "Histidine"},     {"CAG", "Glutamine"},     {"CAU", "Histidine"},
    {"CCA", "Proline"},       {"CCC", "Proline"},       {"CCG", "Proline"},       {"CCU", "Proline"},
    {"CGA", "Arginine"},      {"CGC", "Arginine"},      {"CGG", "Arginine"},      {"CGU", "Arginine"},
    {"CUA", "Leucine"},       {"CUC", "Leucine"},       {"CUG", "Leucine"},       {"CUU", "Leucine"},
    {"GAA", "Glutamic acid"}, {"GAC", "Aspartic acid"}, {"GAG", "Glutamic acid"}, {"GAU", "Aspartic acid"},
    {"GCA", "Alanine"},       {"GCC", "Alanine"},       {"GCG", "Alanine"},       {"GCU", "Alanine"},
    {"GGA", "Glycine"},       {"GGC", "Glycine"},       {"GGG", "Glycine"},       {"GGU", "Glycine"},
    {"GUA", "Valine"},        {"GUC", "Valine"},        {"GUG", "Valine"},        {"GUU", "Valine"},
    {"UAA", "Stop"},          {"UAC", "Tyrosine"},      {"UAG", "Stop"},          {"UAU", "Tyrosine"},
    {"UCA", "Serine"},        {"UCC", "Serine"},        {"UCG", "Serine"},        {"UCU", "Serine"},
    {"UGA", "Stop"},          {"UGC", "Cysteine"},      {"UGG", "Tryptophan"},    {"UGU", "Cysteine"},
    {"UUA", "Leucine"},       {"UUC", "Phenylalanine"}, {"UUG", "Leucine"},       {"UUU", "Phenylalanine"},
};

namespace silkworm::db {

TEST_CASE("for_each") {
    const TemporaryDirectory tmp_dir;
    db::EnvConfig db_config{tmp_dir.path(), /*create*/ true};
    db_config.inmemory = true;
    auto env{db::open_env(db_config)};
    auto txn{env.start_write()};

    static const char* table_name{"GeneticCode"};

    const auto handle{txn.create_map(table_name, mdbx::key_mode::usual, mdbx::value_mode::single)};
    auto table_cursor{txn.open_cursor(handle)};

    std::map<std::string, std::string> data;
    const auto save_all_data{[&data](mdbx::cursor::move_result& entry) {
        data.emplace(entry.key, entry.value);
        return true;
    }};

    // empty table
    for_each(table_cursor, save_all_data);
    REQUIRE(data.empty());

    // populate table
    for (const auto& [key, value] : kGeneticCode) {
        table_cursor.upsert(mdbx::slice{key}, mdbx::slice{value});
    }

    // read entire table
    table_cursor.to_first();
    for_each(table_cursor, save_all_data);
    CHECK(data == kGeneticCode);
    data.clear();

    // late start
    table_cursor.find("UUG");
    for_each(table_cursor, save_all_data);
    REQUIRE(data.size() == 2);
    CHECK(data.at("UUG") == "Leucine");
    CHECK(data.at("UUU") == "Phenylalanine");
    data.clear();

    // early stop
    const auto save_some_data{[&data](mdbx::cursor::move_result& entry) {
        if (entry.value == "Threonine") {
            return false;
        }
        data.emplace(entry.key, entry.value);
        return true;
    }};
    table_cursor.to_first();
    for_each(table_cursor, save_some_data);
    REQUIRE(data.size() == 4);
    CHECK(data.at("AAA") == "Lysine");
    CHECK(data.at("AAC") == "Asparagine");
    CHECK(data.at("AAG") == "Lysine");
    CHECK(data.at("AAU") == "Asparagine");
}

TEST_CASE("for_count") {
    const TemporaryDirectory tmp_dir;
    db::EnvConfig db_config{tmp_dir.path(), /*create*/ true};
    db_config.inmemory = true;
    auto env{db::open_env(db_config)};
    auto txn{env.start_write()};

    static const char* table_name{"GeneticCode"};

    const auto handle{txn.create_map(table_name, mdbx::key_mode::usual, mdbx::value_mode::single)};
    auto table_cursor{txn.open_cursor(handle)};

    std::map<std::string, std::string> data;
    const auto save_all_data{[&data](mdbx::cursor::move_result& entry) {
        data.emplace(entry.key, entry.value);
        return true;
    }};

    // empty table
    for_count(table_cursor, save_all_data, /*max_count=*/5);
    REQUIRE(data.empty());

    // populate table
    for (const auto& [key, value] : kGeneticCode) {
        table_cursor.upsert(mdbx::slice{key}, mdbx::slice{value});
    }

    // read entire table
    table_cursor.to_first();
    for_count(table_cursor, save_all_data, /*max_count=*/100);
    CHECK(data == kGeneticCode);
    data.clear();

    // read some first entries
    table_cursor.to_first();
    for_count(table_cursor, save_all_data, /*max_count=*/5);
    REQUIRE(data.size() == 5);
    CHECK(data.at("AAA") == "Lysine");
    CHECK(data.at("AAC") == "Asparagine");
    CHECK(data.at("AAG") == "Lysine");
    CHECK(data.at("AAU") == "Asparagine");
    CHECK(data.at("ACA") == "Threonine");
    data.clear();

    // late start
    table_cursor.find("UUA");
    for_count(table_cursor, save_all_data, /*max_count=*/3);
    REQUIRE(data.size() == 3);
    CHECK(data.at("UUA") == "Leucine");
    CHECK(data.at("UUC") == "Phenylalanine");
    CHECK(data.at("UUG") == "Leucine");
    data.clear();

    // early stop 1
    const auto save_some_data{[&data](mdbx::cursor::move_result& entry) {
        if (entry.value == "Threonine") {
            return false;
        }
        data.emplace(entry.key, entry.value);
        return true;
    }};
    table_cursor.to_first();
    for_count(table_cursor, save_some_data, /*max_count=*/3);
    REQUIRE(data.size() == 3);
    CHECK(data.at("AAA") == "Lysine");
    CHECK(data.at("AAC") == "Asparagine");
    CHECK(data.at("AAG") == "Lysine");
    data.clear();

    // early stop 2
    table_cursor.to_first();
    for_count(table_cursor, save_some_data, /*max_count=*/5);
    REQUIRE(data.size() == 4);
    CHECK(data.at("AAA") == "Lysine");
    CHECK(data.at("AAC") == "Asparagine");
    CHECK(data.at("AAG") == "Lysine");
    CHECK(data.at("AAU") == "Asparagine");
}

}  // namespace silkworm::db
