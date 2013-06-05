#include <utils.hh>
#include <emilpro.hh>
#include <instructionfactory.hh>
#include <server/cgi-server.hh>
#include <configuration.hh>

#include <string>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace emilpro;

void usage()
{
	printf(
			"cgi-server <configuration-dir> <in-fifo> <out-fifo> [-q] [-f]\n"
			"   -q  Accept quit command\n"
			"   -f  Run in foreground\n"
			);
	exit(1);
}

int main(int argc, const char *argv[])
{
	if (argc < 4)
		usage();

	bool honorQuit = false;
	bool foreground = false;
	std::string baseDirectory = argv[1];
	const char *inFifoName = argv[2];
	const char *outFifoName = argv[3];

	if (argc > 4 && strcmp(argv[4], "-q") == 0)
		honorQuit = true;
	if (argc > 5 && strcmp(argv[5], "-f") == 0)
		foreground = true;

	Configuration::setBaseDirectory(baseDirectory);
	InstructionFactory::instance();
	CgiServer server;

	if (!foreground) {
		pid_t child;

		child = fork();

		if (child < 0) {
			perror("Fork failed?\n");
			exit(3);
		} else if (child == 0) {
			child = fork();

			if (child < 0) {
				perror("Fork failed?\n");
				exit(3);
			} else if (child > 0) {
				// Second parent
				exit(0);
			} else {
			    freopen( "/dev/null", "r", stdin);
			    freopen( "/dev/null", "w", stdout);
			    freopen( "/dev/null", "w", stderr);
			}
		} else {
			// First parent
			exit(0);
		}
	}

	mkdir(baseDirectory.c_str(), 0755);
	mkfifo(inFifoName, S_IRUSR | S_IWUSR);
	mkfifo(outFifoName, S_IRUSR | S_IWUSR);

	while (1)
	{
		char *data;
		size_t sz;

		data = (char *)read_file_timeout(&sz, 1000, "%s", inFifoName);
		if (!data)
			continue;

		std::string cur(data);
		free(data);

		if (honorQuit && cur.substr(0, 4) == "quit")
			return 2;

		server.request(cur);
		std::string reply = server.reply();

		write_file_timeout(reply.c_str(), reply.size(), 1000, "%s", outFifoName);
	}

	return 0;
}
