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


		FILE *fp = popen(fmt("%s /tmp/to-server.fifo /tmp/from-server.fifo %s", cgiHandler.c_str(), tmpFile.c_str()).c_str(), "r");
		if (!fp) {
			unlink(tmpFile.c_str());
			exit(3);
		}
		char buf[512];

		std::string out;
		while(fgets(buf, sizeof(buf), fp)!=NULL)
			out += buf;

		unlink(tmpFile.c_str());
		printf("Sent\n------------\n%s\n------------\n\nReceived\n------------%s\n------------\n", xml.c_str(), out.c_str());

		return out;
	}
};

int main(int argc, const char *argv[])
{
	LocalConnectionHandler localConnectionHandler;

	if (argc != 3) {
		printf("Too few arguments:\n"
				"Usage: test-remote-communication <conf-dir> <cgi-handler>\n"
				);
		exit(1);
	}

	std::string dir = argv[1];
	cgiHandler = argv[2];

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
