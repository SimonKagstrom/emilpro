#!/usr/bin/make

emilpro_deps=libdw-dev libelf-dev elfutils libcurl4-openssl-dev libxml++2.6-dev libgtkmm-3.0-dev libgtksourceviewmm-3.0-dev qtcreator python3 cmake texi2html texinfo

.PHONY: prepare_environment

build_gtk:
	mkdir -p build
	cd build && cmake ..
	make -C build

build_qt:
	mkdir -p build_qt
	cd build_qt && cmake ../src/qt/
	make -C build_qt

build: build_gtk build_qt

prepare_linux:
	sudo apt-get update -y
	sudo apt-get install -y ${emilpro_deps} gcc-multilib debootstrap git time
	cd /tmp && wget https://github.com/aquynh/capstone/archive/3.0.4.tar.gz && tar -xf 3.0.4.tar.gz && cd capstone-3.0.4 && cmake . && make && sudo make install
	sudo pip install robotframework

prepare_environment: prepare_linux
