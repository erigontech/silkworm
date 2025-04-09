# Conan package manager

Conan is a Python-based meta-build system package management tool.
Silkworm uses it for third party packages that are available and well-maintained within the official ["conancenter" repository](https://conan.io/center).
The conancenter repository also contains prebuilt binary packages for common platforms to speed up compilation. Other third party packages are included as git submodules or vendored in [third_party](../third_party) directory.



## Concepts

* conanfile - a config file that defines the list of required libraries and their build options
* recipe - same as conanfile
* recipe version - a semver version of a library
* recipe revision - a checksum identifying a conanfile version for a particular version of a library (a conanfile might have many revision updates for a given recipe version)
* package - a binary artifact from conancenter (or built locally)
* package revision - a checksum identifying a package built from to a particular recipe revision; each recipe revision triggers a build of a new package revision on conancenter CI/CD
* settings - general platform configuration parameters like OS and compiler; can be set as `--settings` from command line, `[settings]` in a profile
* options - library-specific configuration parameters including custom ones; can be set as `--options` from command line, `[options]` in a profile, `self.options` in conanfile
* conf - low-level configuration parameters like `cxxflags`;  can be set as `--conf`  from command line, `[conf]` in a profile
* profile - a static config file that defines common settings, options and conf, can be extended using command line parameters


## Debugging

In [conan.cmake](../cmake/conan.cmake):

	set(CONAN_VERBOSITY "verbose")


## Integration

The default way to integrate conan is to have a custom script that runs [conan install](https://docs.conan.io/2/reference/commands/install.html) command.

Running this command uses [conanfile.py](../conanfile.py) and one of the [profiles](../cmake/profiles) as inputs and produces a bunch of cmake scripts that will make the declared required libraries available to use in CMakeLists.txt and then in the code.

Silkworm integration is not calling `conan install` directly. It is integrated using [cmake-conan](../third_party/cmake-conan) "cmake provider". When the first `find_package(X)` call is encountered in a `CMakeLists.txt` file, cmake consults with the cmake-conan provider, and it will re-run `conan install` command if needed. The parameters to this command are configured in [conan.cmake](../cmake/conan.cmake). The full `conan install` command is printed in the build log.

As a part of `conan install` process it will download header files, source code, prebuilt binary packages, and potentially build the required libraries. That build of conan libraries is happening in a separate cmake process that does not interact with the main one, and its outputs are produced in `$HOME/.conan2`. The only way to pass configuration parameters for this build is via one of the following inputs:

Inputs:
* a profile config from [profiles](../cmake/profiles) with settings is guessed or passed via cmake CONAN_PROFILE parameter
* [conanfile.py](../conanfile.py) with predefined requirements and options
* [conan.cmake](../cmake/conan.cmake) with more fine tuning of options, settings and conf

Outputs:
* downloaded header files and source code for all requirements in `$HOME/.conan2`
* downloaded prebuilt binary packages in `$HOME/.conan2` (if a matching configuration is found on conancenter)
* local builds of packages in `$HOME/.conan2` (if a matching configuration is not found on conancenter)
* cmake integration script for all requirements in `$CMAKE_BINARY_DIR/conan2`

Thus, for example, defining a compilation option in [cmake toolchain](../cmake/toolchain) or CMakeLists.txt has no effect on conan libraries. Their options have to be passed via one of the inputs above.


## Prebuilt binary packages

Silkworm aims to reuse prebuilt binary packages from conancenter as much as possible.
The heaviest of prebuilt requirements are:

* gmp
* grpc
* libtorrent
* openssl
* protobuf

If a library binary packages are not reused from conancenter for any reason, the build time will increase and it needs to be investigated.

The library binary is not reused if there's a mismatch between local options/settings (collected from conanfile, profile and command line parameters) and options/settings that were used when building the library on the conancenter CI/CD. For example, a binary built on conancenter with `options.X=False` is not compatible with a local build defining `options.X=True`. This policy is applied for all options and most settings.

Another common reason for a binary package to not be reused is if there's a requirement with `override=True` in conanfile and its version and options are not matching the version and options of a transitive requirement that the conancenter binary package was built with. For example, libtorrent/2.0.10 binary package can't be reused, because it depends on boost/1.81.0 with default options, but conanfile requires boost/1.83.0 with modified options.

To get a list of available binary binary packages on conancenter run:

	conan list 'grpc/1.67.1:*' -r=conancenter -f=compact

the above command only lists binary packages for the latest recipe revision,
but sometimes some revisions don't have binary packages available.

In this case, list all recipe revisions with dates:

	conan list 'grpc/1.67.1#*' -r=conancenter  

List all binary packages for a given revision:

	conan list 'grpc/1.67.1#c214ddb4e04e8d9a44d3a100defc9706:*' -r=conancenter -f=compact

To list binary packages for all recipe revisions use:

	conan list 'grpc/1.67.1#*:*' -r=conancenter -f=compact


## Updating compilers

The Silkworm compiler version and settings can be freely updated as long as they maintain binary compatibility with the prebuilt binary packages from conancenter. For example, a package built on Linux gcc 11 is binary compatible with Silkworm built on Linux with gcc 12 (all else being equal), so compiling on gcc 12 requires no changes to the conan configuration.

Updating any compiler setting in conan profiles makes it incompatible with available conancenter binary packages.
Therefore the profile settings are dictated and fixed by what's available on conancenter.

The available conancenter platforms by Oct 2024 are:
* Linux gcc 11, no clang
* macOS Apple clang 13, both x86 and arm
* Windows VS 2019 and 2022


## Build cache

Some libraries have special options or overriden requirements and are locally built into `$HOME/.conan2`.
Some compiler options in [compiler_settings.cmake](../cmake/compiler_settings.cmake) might break binary compatibility without conan realizing this. For example, SILKWORM_SANITIZE cmake option breaks binary compatibility. In this case the build cache must be cleared using:

	conan remove --confirm "*"

or simply:

	rm -rf $HOME/.conan2

Silkworm [CI config](../.circleci/config.yml) reuses the conan cache directory between jobs, but makes sure that the cache is binary compatible using a conservative `conan-cache-key`. If any conan configuration is changed then the cache is not reused.


## Updating grpc

Silkworm directly depends on a several grpc transitive requirements:
* abseil
* openssl
* protobuf
* zlib

When updating to a new grpc version, those requirements must be updated to the same versions as grpc requires.
Otherwise the configuration will be incompatible and grpc will be rebuilt from source instead of using the binary package from conancenter.

The required versions can be seen in ["Dependencies" tab on conan.io](https://conan.io/center/recipes/grpc).
