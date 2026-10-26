import multiprocessing
import os
from os.path import join

import sh
from pythonforandroid.logger import shprint, info
from pythonforandroid.recipe import Recipe
from pythonforandroid.util import current_directory


class LibBlsctRecipe(Recipe):
    """Builds navio-core's standalone libblsct.a (plus the univalue and blst
    static archives it needs) for Android.

    This mirrors what libblsct-bindings' setup.py does on desktop:
    a CMake BUILD_LIBBLSCT_ONLY build of navio-core. navio-core vendors
    supranational/blst and compiles it directly in CMake (cmake/blst.cmake),
    picking the aarch64 / x86_64 assembly or the portable C build from
    CMAKE_SYSTEM_PROCESSOR, so the NDK toolchain file is all it needs.
    """

    # navio-core commit pinned by libblsct-bindings (ffi/navio-core.sha) for navio-blsct 0.0.40
    version = '80c87037cf699cb333f173f5f0aee6714d314b19'
    url = 'https://github.com/nav-io/navio-core/archive/{version}.zip'
    sha512sum = '69f81c206eaf3ec9b3829a191c92311b097b022a456f95af4cb41859cfa6f396bbe82a8af490e290c911243531133802e89e98597d0cee81b1513593cb2980d0'

    def built_archives(self, arch):
        build_dir = self.get_build_dir(arch.arch)
        return [
            join(build_dir, 'build', 'lib', 'libblsct.a'),
            join(build_dir, 'build', 'src', 'univalue', 'libunivalue.a'),
            join(build_dir, 'build', 'lib', 'libblst.a'),
        ]

    def include_dirs(self, arch):
        build_dir = self.get_build_dir(arch.arch)
        return [
            join(build_dir, 'src'),
            join(build_dir, 'src', 'blst', 'bindings'),
        ]

    def should_build(self, arch):
        return not all(os.path.exists(f) for f in self.built_archives(arch))

    def build_arch(self, arch):
        env = self.get_recipe_env(arch)
        build_dir = self.get_build_dir(arch.arch)
        num_jobs = str(multiprocessing.cpu_count())

        with current_directory(build_dir):
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
            # blst is named explicitly: a static library's private link
            # dependency is not built by `--target blsct` alone
            shprint(
                sh.cmake,
                '--build', join(build_dir, 'build'),
                '--target', 'blsct', 'blst', 'univalue',
                '-j', num_jobs,
                _env=env,
            )

        missing = [f for f in self.built_archives(arch) if not os.path.exists(f)]
        if missing:
            raise Exception('libblsct build did not produce: {}'.format(missing))


recipe = LibBlsctRecipe()
