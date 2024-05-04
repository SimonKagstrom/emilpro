## Build

MacOS: Remove binutils from the PATH (for the conan build)

```
conan install -of . --build=missing -s build_type=Debug <SRC-DIR>/conanfile.txt
```

MacOS:
```
cmake -GNinja -DCMAKE_PREFIX_PATH="`pwd`/build/Debug/generators/;`brew --prefix binutils`" -DCMAKE_BUILD_TYPE=Debug <SRC-DIR>
ninja
```

![The application on MacOS](doc/emilpro.png)
