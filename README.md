EmilPRO
========
EmilPRO is a graphical disassembler for a large number of instruction
sets. It's a reimplementation and replacement for the Dissy disassembler.

See http://www.emilpro.com for more information!

Build
-----
First install dependencies on your system. EmilPRO needs development packages of the following:

* libelf
* gtkmm-3.0
* gtksourceviewmm-3.0
* libxml++-2.6
* libcurl
* libcapstone (https://github.com/aquynh/capstone)
* flex/bison
* texinfo

For Fedora users:
```sh
sudo dnf -y install elfutils-libelf-devel gtkmm30-devel gtksourceviewmm3-devel \
 libxml++-devel libcurl-devel capstone-devel flex bison
```

For Ubuntu users:
```sh
sudo apt install libelf-dev libgtkmm-3.0-dev libgtksourceviewmm-3.0-dev libxml++2.6-dev \
 libcurl4-openssl-dev libcapstone-dev flex bison elfutils texinfo cmake 
```
Please add ```sudo apt install qt5-default``` if you want to build the QT ui. 


EmilPRO uses cmake for the build, so the process for building it is basically:

```sh
tar -xf emilpro-VER.tar.gz
cd emilpro-VER
mkdir build
cd build

# for the GTK ui:
cmake ..
# .. or for the QT ui:
cmake ../src/qt/

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
 
