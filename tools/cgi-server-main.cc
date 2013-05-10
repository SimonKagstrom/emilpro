#include <utils.hh>
#include <emilpro.hh>
#include <instructionfactory.hh>
#include <server/cgi-server.hh>

#include <string>
#include <fstream>
#include <stdio.h>

using namespace emilpro;

void usage()
{
	printf("cgi-server <in-fifo> <out-fifo>\n");
	exit(1);
}

int main(int argc, const char *argv[])
{
	InstructionFactory::instance();
	CgiServer server;

	if (argc != 3)
		usage();

	const char *inFifoName = argv[1];
	const char *outFifoName = argv[2];

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
