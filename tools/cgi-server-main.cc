#include <utils.hh>
#include <emilpro.hh>
#include <instructionfactory.hh>
#include <server/cgi-server.hh>
#include <configuration.hh>

#include <string>
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
		char *data;
		size_t sz;

		data = (char *)read_file_timeout(&sz, 1000, "%s", inFifoName);
		if (!data)
			continue;

		std::string cur(data);
		free(data);

		server.request(cur);
		std::string reply = server.reply();

		write_file_timeout(reply.c_str(), reply.size(), 1000, "%s", outFifoName);
	}

	return 0;
}
