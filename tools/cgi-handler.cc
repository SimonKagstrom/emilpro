#include <utils.hh>

#include <cgicc/Cgicc.h>
#include <string>
#include <fstream>

using namespace cgicc;

int main(int argc, const char *argv[])
{
	Cgicc cgi;

	const_file_iterator file = cgi.getFile("userfile");

	// Only redirect a valid file
	if (file == cgi.getFiles().end())
		return 0;

	const char *inFifoName = "";
	const char *outFifoName = "";

	std::ofstream outFifo(outFifoName);
	file->writeToStream(outFifo);

	std::ifstream inFifo(inFifoName);

	std::string inData;
	std::string line;

	while (std::getline(inFifo, line))
		std::cout << line;

	return 0;
}
