add_custom_command (OUTPUT binutils.tar.bz2
	COMMAND wget -O binutils.tar.bz2 http://ftp.gnu.org/gnu/binutils/binutils-2.23.2.tar.bz2
)

add_custom_command (OUTPUT binutils/.binutils-built
	COMMAND rm -rf binutils
	COMMAND tar -xf binutils.tar.bz2
	COMMAND mv -f binutils-2.23.2 binutils/
	COMMAND cd binutils && patch -p1 < ${BASE_DIR}/external/binutils/binutils-fix-ineffectual-zero-of-cache.patch
	COMMAND cd binutils && ./configure --enable-targets=all --disable-ld --disable-gold --prefix=`pwd`/../install-binutils && make && make install
	COMMAND cp binutils/include/libiberty.h install-binutils/include/
	COMMAND cp binutils/include/demangle.h install-binutils/include/
	COMMAND touch binutils/.binutils-built
	DEPENDS binutils.tar.bz2
)

add_custom_target(binutils ALL
	DEPENDS binutils/.binutils-built
)
