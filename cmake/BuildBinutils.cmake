add_custom_command(OUTPUT .binutils-downloaded
	COMMAND git clone --depth=1 git://sourceware.org/git/binutils-gdb.git binutils-gdb
	COMMAND touch .binutils-downloaded
)

add_custom_command (OUTPUT binutils/.binutils-built
	COMMAND rm -rf binutils
	COMMAND cp -R binutils-gdb binutils
	COMMAND cd binutils && ./configure --disable-werror --enable-targets=all --disable-ld --disable-gold --prefix=`pwd`/../install-binutils && make && make install
	COMMAND cp binutils/include/libiberty.h install-binutils/include/
	COMMAND cp binutils/include/demangle.h install-binutils/include/
	COMMAND touch binutils/.binutils-built
	DEPENDS .binutils-downloaded
)

add_custom_target(binutils ALL
	DEPENDS binutils/.binutils-built
)
