#include <utils.hh>
#include <emilpro.hh>
#include <instructionfactory.hh>
#include <configuration.hh>
#include <server.hh>

#include <string>
#include <map>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

using namespace emilpro;

static std::string cgiHandler;
static std::string toServerFifo;
static std::string fromServerFifo;

class LocalConnectionHandler : public Server::IConnectionHandler
{
public:
	bool setup(void)
	{
		return true;
	}

	std::string talk(const std::string &xml)
	{
		std::string tmpFile = fmt("/tmp/cgi-handler.%d", getpid());

		int res = write_file(xml.c_str(), xml.size(), "%s", tmpFile.c_str());
		if (res < 0)
			exit(2);


		FILE *fp = popen(fmt("%s %s %s %s",
				cgiHandler.c_str(),
				toServerFifo.c_str(),
				fromServerFifo.c_str(),
				tmpFile.c_str()).c_str(),
				"r");
		if (!fp) {
			unlink(tmpFile.c_str());
			exit(3);
		}
		char buf[512];

		std::string out;
		while(fgets(buf, sizeof(buf), fp)!=NULL)
			out += buf;

		res = pclose(fp);
		if (res != 0) {
			printf("Error returned from cgi-handler\n");
			exit(2);
		}


		unlink(tmpFile.c_str());
		printf("Sent\n------------\n%s\n------------\n\nReceived\n------------%s\n------------\n", xml.c_str(), out.c_str());

		return out;
	}
};

static void usage()
{
	printf(
			"Usage: test-remote-communication <conf-dir> <cgi-handler> <to-server-fifo> <from-server-fifo> [-t TIMESTAMP]\n"
	);
	exit(1);
}

int main(int argc, const char *argv[])
{
	LocalConnectionHandler localConnectionHandler;

	if (argc < 5)
		usage();

	std::string dir = argv[1];
	cgiHandler = argv[2];
	toServerFifo = argv[3];
	fromServerFifo = argv[4];

	uint64_t mocked_timestamp = 0xffffffffffffffffULL;

	for (int i = 5; i < argc; i++) {
		if (strcmp(argv[i], "-t") == 0) {
			i++;

			std::string arg = argv[i];

			if (!string_is_integer(arg))
				usage();
			mocked_timestamp = string_to_integer(arg);
		}
	}

	if (mocked_timestamp != 0xffffffffffffffffULL)
		mock_utc_timestamp(mocked_timestamp);

	// Reads all models
	Configuration::setBaseDirectory(dir);
	EmilPro::init();

	Server &server = Server::instance();

	server.setConnectionHandler(localConnectionHandler);
	if (!server.connect())
		return 1;

	server.stop();

	return 0;
}
