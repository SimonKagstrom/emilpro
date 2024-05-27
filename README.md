# EmilPRO
A graphical disassembler for multiple architectures

![The application on MacOS](doc/emilpro.png)

## Preparations for build

### Debian/Ubuntu

(untested)

`binutils-multiarch-dev`

### Fedora

(No multiarch binutils?)

### MacOS

```
brew install binutils qt6 conan
```

## Build

### MacOS

Remove binutils from the PATH (for the conan build)

```
conan install -of . --build=missing -s build_type=Debug <SRC-DIR>/conanfile.txt
```

```
cmake -GNinja -DCMAKE_PREFIX_PATH="`pwd`/build/Debug/generators/;`brew --prefix binutils`" -DCMAKE_BUILD_TYPE=Debug <SRC-DIR>
ninja
```
