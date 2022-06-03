/*
   Copyright 2017 The Abseil Authors.

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

// Ported from Abseil to Silkworm core.

#ifndef SILKWORM_COMMON_OPTIMIZATION_H_
#define SILKWORM_COMMON_OPTIMIZATION_H_

#ifdef __has_builtin
#define SILKWORM_HAVE_BUILTIN(x) __has_builtin(x)
#else
#define SILKWORM_HAVE_BUILTIN(x) 0
#endif

#if SILKWORM_HAVE_BUILTIN(__builtin_expect) || (defined(__GNUC__) && !defined(__clang__))
#define SILKWORM_PREDICT_FALSE(x) (__builtin_expect(false || (x), false))
#define SILKWORM_PREDICT_TRUE(x) (__builtin_expect(false || (x), true))
#else
#define SILKWORM_PREDICT_FALSE(x) (x)
#define SILKWORM_PREDICT_TRUE(x) (x)
#endif

#endif  // SILKWORM_COMMON_OPTIMIZATION_H_
