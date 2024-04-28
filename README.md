## Build

```bash
conan install -of . --build=missing -s build_type=Debug -pr <SRC>/conanprofile-macos.txt <SRC-DIR>/conanfile.txt
cmake -GNinja -DCMAKE_PREFIX_PATH="`pwd`/build/Debug/generators/;`brew --prefix binutils`" -DCMAKE_BUILD_TYPE=Debug <SRC-DIR>
ninja
```
