import multiprocessing
import os
from os.path import join

import sh
from pythonforandroid.logger import shprint, info
from pythonforandroid.recipe import Recipe
from pythonforandroid.util import current_directory


class LibBlsctRecipe(Recipe):
    """Builds navio-core's standalone libblsct.a (plus the univalue, mcl and
    bls static archives it needs) for Android.

    This mirrors what libblsct-bindings' setup.py does on desktop:
    a CMake BUILD_LIBBLSCT_ONLY build of navio-core. The mcl and bls
    sub-libraries are driven by their own GNU Makefiles via
    ExternalProject_Add; navio-core's cmake/bls.cmake forwards
    "CC=${CMAKE_C_COMPILER} ${CMAKE_C_COMPILER_ARG1}" to them, which loses
    the --target flag the NDK toolchain passes via CMAKE_C_COMPILER_TARGET.
    To avoid silently building host-arch archives, we build mcl and bls
    ourselves first with the full cross-compiler invocation; the
    ExternalProject build commands then find the archives up to date and
    do nothing.
    """

    # navio-core commit pinned by libblsct-bindings' setup.py (tag v0.1.0)
    version = '459f3e8e9bc216ac82f2c472a84cc7540fa97f0b'
    url = 'https://github.com/nav-io/navio-core/archive/{version}.zip'
    sha512sum = 'e3e6e778da44deb6c31c12a1695ea676e8e542032d28a3d8fce2997db26e1b837b37e73bc2322ac7a4c09cfafabbaa526a58eb800bf4338981ca2cd60e57ff06'

    # mcl/bls GNU makefiles take the target cpu via ARCH=
    _MCL_ARCH = {
        'arm64-v8a': 'aarch64',
        'armeabi-v7a': 'armv7l',
        'x86_64': 'x86_64',
        'x86': 'x86',
    }

    def built_archives(self, arch):
        build_dir = self.get_build_dir(arch.arch)
        return [
            join(build_dir, 'build', 'lib', 'libblsct.a'),
            join(build_dir, 'build', 'src', 'univalue', 'libunivalue.a'),
            join(build_dir, 'src', 'bls', 'lib', 'libbls384_256.a'),
            join(build_dir, 'src', 'bls', 'mcl', 'lib', 'libmcl.a'),
        ]

    def include_dirs(self, arch):
        build_dir = self.get_build_dir(arch.arch)
        return [
            join(build_dir, 'src'),
            join(build_dir, 'src', 'bls', 'include'),
            join(build_dir, 'src', 'bls', 'mcl', 'include'),
        ]

    def should_build(self, arch):
        return not all(os.path.exists(f) for f in self.built_archives(arch))

    def build_arch(self, arch):
        env = self.get_recipe_env(arch)
        build_dir = self.get_build_dir(arch.arch)
        num_jobs = str(multiprocessing.cpu_count())
        mcl_arch = self._MCL_ARCH[arch.arch]

        # same variable set as navio-core's cmake/bls.cmake ExternalProject
        # build commands, but with the full NDK cross-compiler invocations
        make_vars = [
            'LLVM_OPT_VERSION=',
            'MCL_USE_GMP=0',
            'MCL_USE_OMP=0',
            'ARCH=' + mcl_arch,
            'CC=' + env['CC'],
            'CXX=' + env['CXX'],
            'AR=' + env['AR'] + ' r',
            'CFLAGS_USER=',
            'LDFLAGS=',
        ]

        with current_directory(build_dir):
            info('Cross-building mcl for {}'.format(arch.arch))
            shprint(
                sh.make, '-j', num_jobs,
                'MCL_USE_LLVM=0', *make_vars,
                '-C', join(build_dir, 'src', 'bls', 'mcl'),
                'lib/libmcl.a',
                _env=env,
            )

            info('Cross-building bls for {}'.format(arch.arch))
            shprint(
                sh.make, '-j', num_jobs,
                'BLS_ETH=1', *make_vars,
                '-C', join(build_dir, 'src', 'bls'),
                'lib/libbls384_256.a',
                _env=env,
            )

            info('Configuring navio-core (BUILD_LIBBLSCT_ONLY) for {}'.format(arch.arch))
            toolchain = join(
                self.ctx.ndk_dir, 'build', 'cmake', 'android.toolchain.cmake')
            shprint(
                sh.cmake,
                '-S', build_dir,
                '-B', join(build_dir, 'build'),
                '-DCMAKE_TOOLCHAIN_FILE=' + toolchain,
                '-DANDROID_ABI=' + arch.arch,
                '-DANDROID_PLATFORM=android-{}'.format(self.ctx.ndk_api),
                '-DBUILD_LIBBLSCT_ONLY=ON',
                '-DCMAKE_BUILD_TYPE=Release',
                '-DBUILD_TESTS=OFF',
                '-DBUILD_BENCH=OFF',
                '-DCMAKE_POSITION_INDEPENDENT_CODE=ON',
                _env=env,
            )

            info('Building libblsct for {}'.format(arch.arch))
            shprint(
                sh.cmake,
                '--build', join(build_dir, 'build'),
                '--target', 'blsct', 'univalue',
                '-j', num_jobs,
                _env=env,
            )

        missing = [f for f in self.built_archives(arch) if not os.path.exists(f)]
        if missing:
            raise Exception('libblsct build did not produce: {}'.format(missing))


recipe = LibBlsctRecipe()
