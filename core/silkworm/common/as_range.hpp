/*
   Copyright 2020-2021 The Silkworm Authors

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

#ifndef SILKWORM_AS_RANGE
#define SILKWORM_AS_RANGE

#include <algorithm>

namespace as_range
{
    template<typename Cont, typename F>
    F for_each(Cont& c, F&& f)
    {
        return std::for_each(std::begin(c), std::end(c), std::forward<F>(f));
    }

    template<typename Cont, typename F>
    bool all_of(Cont& c, F&& f)
    {
        return std::all_of(std::begin(c), std::end(c), std::forward<F>(f));
    }

    template<typename Cont, typename F>
    bool any_of(Cont& c, F&& f)
    {
        return std::any_of(std::begin(c), std::end(c), std::forward<F>(f));
    }

    template<typename Cont, typename F>
    bool none_of(Cont& c, F&& f)
    {
        return std::none_of(std::begin(c), std::end(c), std::forward<F>(f));
    }

    template<typename Cont, typename T>
    decltype(auto) find(Cont& c, const T& value)
    {
        return std::find(std::begin(c), std::end(c), value);
    }

    template<typename Cont, typename F>
    decltype(auto) find_if(Cont& c,  F&& f)
    {
        return std::find_if(std::begin(c), std::end(c), std::forward<F>(f));
    }

    template<typename Cont, typename F>
    decltype(auto) find_if_not(Cont& c,  F&& f)
    {
        return std::find_if_not(std::begin(c), std::end(c), std::forward<F>(f));
    }

    template<typename Cont, typename F>
    decltype(auto) count_if(Cont& c,  F&& f)
    {
        return std::count_if(std::begin(c), std::end(c), std::forward<F>(f));
    }

    template<typename Cont, typename F>
    void sort(Cont& c,  F&& f)
    {
        std::sort(std::begin(c), std::end(c), std::forward<F>(f));
    }

    template<typename Cont, typename F>
    void stable_sort(Cont& c,  F&& f)
    {
        std::stable_sort(std::begin(c), std::end(c), std::forward<F>(f));
    }
}


#endif // SILKWORM_AS_RANGE
