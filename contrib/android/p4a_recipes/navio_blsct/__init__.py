import os
import re
import shutil
from os.path import join

import sh
from pythonforandroid.logger import shprint, info
from pythonforandroid.recipe import Recipe
from pythonforandroid.util import current_directory, ensure_dir


class NavioBlsctRecipe(Recipe):
    """The navio-blsct python bindings (SWIG wrapper around libblsct).

    PyPI only ships macOS/Linux wheels and the sdist build assumes a native
    (non-cross) toolchain, so instead of running the upstream setup.py we
    drive the same steps by hand: SWIG-generate the wrapper from
    ffi/python/blsct/blsct.i, cross-compile it with the NDK, link the
    static archives produced by the libblsct recipe, and copy the package
    into the target python's site-packages.
    """

    # libblsct-bindings commit for the 0.0.38 release
    version = '4501efb3be35b35f12495d768ce8c7ff2b9a9977'
    url = 'https://github.com/nav-io/libblsct-bindings/archive/{version}.zip'
    sha512sum = 'd9e88a83fee56d84f942e4d3435e729f498c21717593bbb78fa22648bb6905ba6b220af5f97242c4f668b070f1452f8cf9361d6aeb2abf31c95feaa57106b49e'

    depends = ['python3', 'libblsct']
    need_stl_shared = True  # the wrapper is C++

    _OVERRIDE_SHIM = (
        'try:\n'
        '    from typing import override\n'
        'except ImportError:  # python < 3.12\n'
        '    def override(_f):\n'
        '        return _f\n'
    )

    def _patch_typing_override(self, pkg_dir):
        """typing.override only exists on python >= 3.12, but the p4a target
        python is older; rewrite the imports with a no-op fallback."""
        pattern = re.compile(r'^from typing import (.+?)[; ]*$')
        for root, _dirs, files in os.walk(pkg_dir):
            for fn in files:
                if not fn.endswith('.py'):
                    continue
                path = join(root, fn)
                with open(path, encoding='utf-8') as f:
                    lines = f.readlines()
                changed = False
                out = []
                for line in lines:
                    m = pattern.match(line.rstrip('\n'))
                    if m and 'override' in [n.strip() for n in m.group(1).split(',')]:
                        names = [n.strip() for n in m.group(1).split(',')
                                 if n.strip() and n.strip() != 'override']
                        if names:
                            out.append('from typing import {}\n'.format(', '.join(names)))
                        out.append(self._OVERRIDE_SHIM)
                        changed = True
                    else:
                        out.append(line)
                if changed:
                    with open(path, 'w', encoding='utf-8') as f:
                        f.writelines(out)
                    info('patched typing.override fallback into {}'.format(fn))

    def should_build(self, arch):
        return not os.path.exists(
            join(self.ctx.get_python_install_dir(arch.arch), 'blsct', '_blsct.so'))

    def build_arch(self, arch):
        env = self.get_recipe_env(arch)
        build_dir = self.get_build_dir(arch.arch)
        py_dir = join(build_dir, 'ffi', 'python')
        pkg_dir = join(py_dir, 'blsct')

        libblsct = self.get_recipe('libblsct', self.ctx)
        core_dir = libblsct.get_build_dir(arch.arch)

        python_recipe = self.ctx.python_recipe
        py_include = python_recipe.include_root(arch.arch)
        py_link_root = python_recipe.link_root(arch.arch)
        py_link_version = python_recipe.link_version

        with current_directory(py_dir):
            # blsct/blsct.i includes "../blsct.i" (the shared SWIG contract)
            # and the blsct.h header via "../../navio-core/...", mirroring
            # what upstream setup.py arranges in the source tree.
            shutil.copy2(join(build_dir, 'ffi', 'blsct.i'), join(py_dir, 'blsct.i'))
            navio_core_link = join(py_dir, 'navio-core')
            if os.path.islink(navio_core_link) or os.path.exists(navio_core_link):
                if os.path.islink(navio_core_link):
                    os.unlink(navio_core_link)
                else:
                    shutil.rmtree(navio_core_link)
            os.symlink(core_dir, navio_core_link)

            info('SWIG-generating the blsct wrapper')
            # the wrapper #includes "../../navio-core/..." relative to its own
            # location, so it must live two directories below py_dir (where
            # the navio-core symlink is), like upstream's build/temp dir
            wrap_dir = join(py_dir, 'build', 'wrap')
            ensure_dir(wrap_dir)
            wrap_cxx = join(wrap_dir, 'blsct_wrap.cpp')
            shprint(
                sh.swig, '-python', '-c++',
                '-o', wrap_cxx,
                '-outdir', pkg_dir,
                join(pkg_dir, 'blsct.i'),
                _env=env,
            )

            info('Cross-compiling the blsct wrapper for {}'.format(arch.arch))
            includes = ' '.join(
                '-I' + d for d in ([py_include] + libblsct.include_dirs(arch)))
            shprint(
                sh.bash, '-c',
                '{cxx} -std=c++20 -fPIC -O2 {includes} '
                '-c {wrap} -o {obj}'.format(
                    cxx=env['CXX'], includes=includes, wrap=wrap_cxx,
                    obj=join(wrap_dir, 'blsct_wrap.o')),
                _env=env,
            )

            info('Linking _blsct.so')
            archives = ' '.join(libblsct.built_archives(arch))
            shprint(
                sh.bash, '-c',
                '{cxx} -shared {ldflags} -o {out} {obj} '
                '{archives} -L{py_link_root} -lpython{py_link_version} '
                '-lc++_shared'.format(
                    cxx=env['CXX'],
                    ldflags=env.get('LDFLAGS', ''),
                    out=join(pkg_dir, '_blsct.so'),
                    obj=join(wrap_dir, 'blsct_wrap.o'),
                    archives=archives,
                    py_link_root=py_link_root,
                    py_link_version=py_link_version),
                _env=env,
            )
            shprint(
                sh.bash, '-c',
                '{strip} {so}'.format(
                    strip=env['STRIP'], so=join(pkg_dir, '_blsct.so')),
                _env=env,
            )

        self._patch_typing_override(pkg_dir)

        info('Installing the blsct package into site-packages')
        dest = join(self.ctx.get_python_install_dir(arch.arch), 'blsct')
        if os.path.exists(dest):
            shutil.rmtree(dest)
        ensure_dir(os.path.dirname(dest))
        shutil.copytree(
            pkg_dir, dest,
            ignore=shutil.ignore_patterns('*.i', '__pycache__'))
        expected = [join(dest, '_blsct.so'), join(dest, 'blsct.py')]
        missing = [f for f in expected if not os.path.exists(f)]
        if missing:
            raise Exception('navio-blsct install is missing: {}'.format(missing))


recipe = NavioBlsctRecipe()
