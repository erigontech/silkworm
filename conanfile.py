#    Copyright 2023 The Silkworm Authors

#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at

#        http://www.apache.org/licenses/LICENSE-2.0

#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

from conan import ConanFile


class SilkwormRecipe(ConanFile):
    settings = 'os', 'compiler', 'build_type', 'arch'
    generators = 'cmake_find_package'

    def requirements(self):
        self.requires('catch2/2.13.9')
        self.requires('magic_enum/0.8.2')
        self.requires('ms-gsl/4.0.0')
        self.requires('nlohmann_json/3.11.3')
        self.requires('tl-expected/1.1.0')
        self.requires('zlib/1.3.1')
        if self.settings.arch == 'wasm':
            return

        self.requires('abseil/20230125.3')
        self.requires('asio-grpc/2.9.2')
        self.requires('benchmark/1.6.1')
        self.requires('boost/1.83.0')
        self.requires('cli11/2.2.0')
        self.requires('gmp/6.2.1')
        self.requires('grpc/1.54.3')
        self.requires('gtest/1.12.1')
        self.requires('jwt-cpp/0.6.0')
        self.requires('mimalloc/2.1.2')
        self.requires('openssl/3.2.1')
        self.requires('protobuf/3.21.12')
        self.requires('roaring/1.1.2')
        self.requires('snappy/1.1.7')
        self.requires('spdlog/1.12.0')
        self.requires('sqlitecpp/3.3.0')
        self.requires('tomlplusplus/3.3.0')

    def configure(self):
        self.options['asio-grpc'].local_allocator = 'boost_container'

        # Conan Center has Windows binaries built only with msvc16 and mimalloc built only with option override=False.
        # In order to build mimalloc with override=True we could switch to msvc17 compiler but this would trigger a full
        # rebuild from sources of all dependencies increasing build time a lot, so we prefer to keep mimalloc override
        # disabled on Windows.
        # The same applies also for boost with option asio_no_deprecated, so we skip configuration entirely on Windows.
        if self.settings.os == 'Windows':
            return

        # mimalloc override=True causes a crash on macOS at startup in rpcdaemon, so we just enable it on Linux
        if self.settings.os == 'Linux':
            self.options['mimalloc'].override = True

        self.options['boost'].asio_no_deprecated = True

        # Disable building unused boost components
        # note: changing default options above forces a boost rebuild anyway
        for component in self.boost_components_unused():
            setattr(self.options['boost'], 'without_' + component, True)

    @staticmethod
    def boost_components_unused() -> set[str]:
        components_all = [
            'atomic',
            'chrono',
            'container',
            'context',
            'contract',
            'coroutine',
            'date_time',
            'exception',
            'fiber',
            'filesystem',
            'graph',
            'graph_parallel',
            'iostreams',
            'json',
            'locale',
            'log',
            'math',
            'mpi',
            'nowide',
            'program_options',
            'python',
            'random',
            'regex',
            'serialization',
            'stacktrace',
            'system',
            'test',
            'thread',
            'timer',
            'type_erasure',
            'url',
            'wave',
        ]

        components_used = [
            # asio-grpc requires:
            'container',

            # silkworm requires:
            'iostreams',
            'system',
            'thread',

            # Boost::iostreams requires
            'random',
            'regex',

            # Boost::thread requires:
            'atomic',
            'chrono',
            'date_time',
            'exception',
        ]

        return set(components_all) - set(components_used)
