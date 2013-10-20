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
			"cgi-server <configuration-dir> [-q] [-f] [-t TIMESTAMP]\n"
			"   -q              Accept quit command\n"
			"   -f              Run in foreground\n"
			"   -t  TIMESTAMP   Set time to TIMESTAMP\n"
			);
	exit(1);
}

std::string baseDirectory;

static void on_term(int sig)
{
	std::string pidFile = baseDirectory + "/server.pid";

	unlink(pidFile.c_str());

	exit(0);
}

int main(int argc, const char *argv[])
{
	if (argc < 2)
		usage();

	bool honorQuit = false;
	bool foreground = false;
	baseDirectory = argv[1];
	std::string inFifoName = baseDirectory + "/to-server.fifo";
	std::string outFifoName = baseDirectory + "/from-server.fifo";
	uint64_t mocked_timestamp = 0xffffffffffffffffULL;

	for (int i = 2; i < argc; i++) {
		if (strcmp(argv[i], "-t") == 0) {
			i++;

			std::string arg = argv[i];

			if (!string_is_integer(arg))
				usage();
			mocked_timestamp = string_to_integer(arg);
		}
		else if (strcmp(argv[i], "-q") == 0)
			honorQuit = true;
		else if (strcmp(argv[i], "-f") == 0)
			foreground = true;
	}

	if (mocked_timestamp != 0xffffffffffffffffULL)
		mock_utc_timestamp(mocked_timestamp);

	Configuration::setBaseDirectory(baseDirectory);
	Configuration::instance().setReadStoredModels(false);

	EmilPro::init();
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
			    stdin = freopen( "/dev/null", "r", stdin);
			    stdout = freopen( "/dev/null", "w", stdout);
			    stderr = freopen( "/dev/null", "w", stderr);
			}
		} else {
			// First parent
			exit(0);
		}
	}

	mkdir(baseDirectory.c_str(), 0755);
	mkfifo(inFifoName.c_str(), S_IRUSR | S_IWUSR);
	mkfifo(outFifoName.c_str(), S_IRUSR | S_IWUSR);

	std::string pidString = fmt("%d\n", (int)getpid());
	std::string pidFile = baseDirectory + "/server.pid";

	signal(SIGINT, on_term);
	signal(SIGTERM, on_term);

	write_file((void *)pidString.c_str(), pidString.size(), "%s", pidFile.c_str());

	int ret = 0;

	while (1)
	{
		char *data;
		size_t sz;

		data = (char *)read_file_timeout(&sz, 1000, "%s", inFifoName.c_str());
		if (!data)
			continue;

		std::string cur(data);
		free(data);

		if (honorQuit && cur.substr(0, 4) == "quit") {
			ret = 2;
			break;
		}

		server.request(cur);
		std::string reply = server.reply();

		write_file_timeout(reply.c_str(), reply.size(), 1000, "%s", outFifoName.c_str());
	}

	unlink(pidFile.c_str());

	return ret;
}
