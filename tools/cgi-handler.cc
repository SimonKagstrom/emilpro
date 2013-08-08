#include <utils.hh>

#include <cgicc/Cgicc.h>
#include <string>
#include <fstream>

using namespace cgicc;

void usage()
{
	printf(
			"Usage: cgi-handler <configuration-dir> [file-to-read]\n"
			"\n"
			"If [file-to-read] is given, it's used in test-mode.\n"
			);
	exit(2);
}

int main(int argc, const char *argv[])
{
	std::string data;
	bool testMode = false;

	if (argc >= 3) {
		testMode = true;
	} else if (argc < 2)
		usage();

	if (strcmp(argv[1], "-h") == 0)
		usage();

	std::string baseDir = argv[1];

	if (!testMode) {
		Cgicc cgi;

		const_file_iterator file = cgi.getFile("userfile");

		// Only redirect a valid file
		if (file == cgi.getFiles().end())
			return 1;

		data = file->getData();
	} else {
		size_t sz;
		const char *rawData = (const char *)read_file(&sz, "%s", argv[2]);

		if (!rawData) {
			return 1;
		}

		data = rawData;
	}

	std::string toServerFifoName = baseDir + "/to-server.fifo";
	std::string fromServerFifoName = baseDir + "/from-server.fifo";
	int rv;

	rv = write_file_timeout(data.c_str(), data.size(), 1000, "%s", toServerFifoName.c_str());
	if (rv < 0)
		return 1;

	char *p;
	size_t sz;

	p = (char *)read_file_timeout(&sz, 1000, "%s", fromServerFifoName.c_str());
	if (!p)
		return 2;
	printf("%s", p);

	free(p);

	return 0;
}
