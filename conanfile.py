# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

from conan import ConanFile


class SilkwormRecipe(ConanFile):
    settings = 'os', 'compiler', 'build_type', 'arch'
    generators = 'CMakeDeps'

    def requirements(self):
        self.requires('catch2/3.6.0')
        self.requires('magic_enum/0.8.2')
        self.requires('ms-gsl/4.0.0')
        self.requires('nlohmann_json/3.11.3')
        self.requires('tl-expected/1.1.0')
        self.requires('zlib/1.3.1')
        if self.settings.arch == 'wasm':
            return

        self.requires('abseil/20240116.2', override=True)
        self.requires('asio-grpc/2.9.2')
        self.requires('benchmark/1.6.1')
        self.requires('boost/1.83.0', override=True)
        self.requires('cli11/2.2.0')
        self.requires('gmp/6.2.1')
        # fix to an older recipe revision due to missing binary packages for the latest revision
        # see https://github.com/conan-io/conan-center-index/issues/26959
        self.requires('grpc/1.67.1#c214ddb4e04e8d9a44d3a100defc9706', override=True)
        self.requires('gtest/1.12.1')
        self.requires('jwt-cpp/0.6.0')
        self.requires('libtorrent/2.0.10')
        self.requires('mimalloc/2.1.2')
        self.requires('openssl/3.4.1', override=True)
        self.requires('protobuf/5.27.0', override=True)
        self.requires('roaring/1.1.2')
        self.requires('snappy/1.1.7')
        self.requires('spdlog/1.12.0')
        self.requires('sqlitecpp/3.3.0')
        self.requires('tomlplusplus/3.3.0')
        self.requires('libdeflate/1.23')

    def configure(self):
        self.options['asio-grpc'].local_allocator = 'boost_container'

        if (self.settings.os == 'Linux') and (self.settings.compiler == 'clang'):
            self.options['grpc'].with_libsystemd = False

        # Disable Catch2 version 3.x.x signal handling on WASM
        if self.settings.arch == 'wasm':
            self.options['catch2'].no_posix_signals = True

        self.configure_boost()

    def configure_boost(self):
        # on Windows rebuilding boost from sources increases the build time a lot, so we skip configuration
        # hoping it doesn't break with asio_no_deprecated = False
        if self.settings.os == 'Windows':
            return

        self.options['boost'].asio_no_deprecated = True

        if self.settings.os == 'Macos':
            cmake_osx_deployment_target = '10.14'
            os_version_min_flag = f'-mmacosx-version-min={cmake_osx_deployment_target}'
            self.options['boost'].extra_b2_flags = f'cxxflags="{os_version_min_flag}" linkflags="{os_version_min_flag}"'

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
            'wave',
        ]

        components_used = [
            # asio-grpc requires:
            'container',

            # silkworm requires:
            'iostreams',
            'system',
            'thread',
            'url',

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
