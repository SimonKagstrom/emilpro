#!/usr/bin/make

emilpro_deps=libdw-dev libelf-dev elfutils libcurl4-openssl-dev libxml++2.6-dev libgtkmm-3.0-dev libgtksourceviewmm-3.0-dev libqt4-dev python3 cmake texi2html

.PHONY: prepare_environment

build:
	mkdir -p build build-tests build-tools
	cd build && cmake ..
	make -C build

prepare_linux:
	sudo apt-get update -qq
	sudo apt-get install -y ${emilpro_deps} gcc-multilib debootstrap git time
	sudo pip install robotframework

prepare_environment: prepare_linux
