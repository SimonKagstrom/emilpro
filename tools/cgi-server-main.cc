#include <utils.hh>
#include <emilpro.hh>
#include <instructionfactory.hh>
#include <server/cgi-server.hh>
#include <configuration.hh>

#include <string>
#include <fstream>
#include <stdio.h>
#include <sys/stat.h>

using namespace emilpro;

void usage()
{
	printf("cgi-server <configuration-dir> <in-fifo> <out-fifo>\n");
	exit(1);
}

int main(int argc, const char *argv[])
{
	if (argc != 4)
		usage();

	std::string baseDirectory = argv[1];
	const char *inFifoName = argv[2];
	const char *outFifoName = argv[3];

	mkfifo(inFifoName, S_IRUSR | S_IWUSR);
	mkfifo(outFifoName, S_IRUSR | S_IWUSR);

	Configuration::setBaseDirectory(baseDirectory);
	InstructionFactory::instance();
	CgiServer server;

	while (1)
	{
		std::ifstream inFifo(inFifoName);

		std::string inData;
		std::string line;

		while (std::getline(inFifo, line))
			inData += line + '\n';

		server.request(inData);
		std::string reply = server.reply();

		std::ofstream outFifo(outFifoName);
		outFifo << reply;
	}

	return 0;
}
