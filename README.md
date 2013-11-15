EmilPRO
========
EmilPRO is a graphical disassembler for a large number of instruction
sets. It's a reimplementation and replacement for the Dissy disassembler.

See http://www.emilpro.com for more information!

Build
-----
EmilPRO uses cmake for the build, so the process for building it is basically:

```sh
tar -xf emilpro-VER.tar.gz
cd emilpro-VER
mkdir build
cd build

cmake ..

make
```

The first time EmilPRO is built, it will download and build binutils, so this
will take quite a bit of time.

Install
-------
The binary is self-contained, so just copy **emilpro** to somewhere in your path.

Name
----
The name is a pun on IDA pro.


Authors
-------
* Simon Kågström <simon.kagstrom@gmail.com>
 