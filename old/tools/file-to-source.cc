#include <utils.hh>

#include <string>
#include <stdio.h>

int main(int argc, const char *argv[])
{
	if (argc < 4) {
		printf("Too few arguments:\n"
				"Usage: XXX outfile.h symbol_name infile...\n"
				);
		exit(1);
	}

	std::string in;
	for (int i = 3; i < argc; i++) {
		size_t sz;
		char *p = (char *)read_file(&sz, "%s", argv[i]);
		if (!p) {
			printf("Can't read %s\n", argv[i]);
			exit(1);
		}
		in += p;
	}

	if (in.find("<?xml version=\"1.0\"") == std::string::npos) {
		in =	"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				"<emilpro>\n"
				+ in +
				"</emilpro>\n";
	}

	std::string out =
			fmt("#pragma once\n"
			"#include <string>\n"
			"\n"
			"std::string %s = \n\"", argv[2]);
	out += escape_string_for_c(in);
	out += "\"; // END";

	int v = write_file((void *)out.c_str(), out.size(), "%s", argv[1]);
	if (v != 0) {
		fprintf(stderr, "Can't write: %d\n", v);
		exit(1);
	}

	return 0;
}
