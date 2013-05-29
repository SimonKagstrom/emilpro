#include <utils.hh>

#include <cgicc/Cgicc.h>
#include <string>
#include <fstream>

using namespace cgicc;

void usage()
{
	printf(
			"Usage: cgi-handler [file-to-read]\n"
			"\n"
			"If [file-to-read] is given, it's used in test-mode.\n"
			);
	exit(2);
}

int main(int argc, const char *argv[])
{
	std::string data;
	bool testMode = false;

	if (argc >= 2) {
		testMode = true;

		if (strcmp(argv[1], "-h") == 0)
			usage();
	}

	if (!testMode) {
		Cgicc cgi;

		const_file_iterator file = cgi.getFile("userfile");

		// Only redirect a valid file
		if (file == cgi.getFiles().end())
			return 1;

		data = file->getData();
	} else {
		size_t sz;
		const char *rawData = (const char *)read_file(&sz, "%s", argv[1]);

		if (!rawData) {
			return 1;
		}

		data = rawData;
	}

	const char *inFifoName = "";
	const char *outFifoName = "";

	std::ofstream outFifo(outFifoName);
	outFifo << data;

	std::ifstream inFifo(inFifoName);

	std::string inData;
	std::string line;

	while (std::getline(inFifo, line))
		std::cout << line;

	return 0;
}
