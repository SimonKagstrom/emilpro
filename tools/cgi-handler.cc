#include <utils.hh>

#include <cgicc/Cgicc.h>
#include <string>
#include <fstream>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>

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
	struct flock fl = {F_WRLCK, SEEK_SET,      0,      0,    0};
                    // l_type   l_whence  l_start  l_len  l_pid
	int lockFd;
	std::string data;
	bool testMode = false;
	int ret = 0;
	char *p;
	size_t sz;
	std::string ip = fmt("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
					"<emilpro>\n"
					"  <ServerTimestamps>\n"
					"    <CurrentIP>%s</CurrentIP>\n"
					"  </ServerTimestamps>\n"
					"</emilpro>\n",
					getenv("REMOTE_ADDR"));

	if (argc >= 3) {
		testMode = true;
	} else if (argc < 2)
		usage();

	if (strcmp(argv[1], "-h") == 0)
		usage();

	fl.l_pid = getpid();

	std::string baseDir = argv[1];
	std::string lockFile = baseDir + "/cgi-handler.lock";
	std::string toServerFifoName = baseDir + "/to-server.fifo";
	std::string fromServerFifoName = baseDir + "/from-server.fifo";
	int rv;

	lockFd = open(lockFile.c_str(), O_RDWR | O_CREAT, 0600);

	panic_if (lockFd < 0,
			"Can't open lock file %s\n", lockFile.c_str());

	panic_if (fcntl(lockFd, F_SETLKW, &fl) == -1,
			"fcntl failed\n");

	if (!testMode) {
		Cgicc cgi;

		const_file_iterator file = cgi.getFile("userfile");

		// Only redirect a valid file
		if (file == cgi.getFiles().end()) {
			ret = 1;
			goto out;
		}

		data = file->getData();
	} else {
		size_t sz;
		const char *rawData = (const char *)read_file(&sz, "%s", argv[2]);

		if (!rawData) {
			ret = 1;
			goto out;
		}

		data = rawData;
	}

	rv = write_file_timeout(ip.c_str(), ip.size(), 1000, "%s", toServerFifoName.c_str());
	if (rv < 0) {
		ret = 1;
		goto out;
	}

	p = (char *)read_file_timeout(&sz, 1000, "%s", fromServerFifoName.c_str());
	if (!p) {
		ret = 2;
		goto out;
	}
	printf("%s", p);

	free(p);
out:
	fl.l_type = F_UNLCK;

	panic_if (fcntl(lockFd, F_SETLK, &fl) == -1,
			"fcntl unlock failed");
	close(lockFd);

	return ret;
}
