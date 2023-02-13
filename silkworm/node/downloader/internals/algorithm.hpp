/*
   Copyright 2022 The Silkworm Authors

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

#pragma once

#include <stack>
#include <vector>

// move (non copy) elements from a source container appending them to destination container
template <typename T>
auto move_at_end(std::vector<T>& destination, std::vector<T>& source) {
    destination.insert(destination.end(), std::make_move_iterator(source.begin()),
                       std::make_move_iterator(source.end()));
}

// bulk insert for stacks
template <typename T>
void push_all(std::stack<T>& destination, std::vector<T>& source) {
    for (auto& element : source) destination.push(element);
}
