#include <utils.hh>

#include <string>
#include <stdio.h>

int main(int argc, const char *argv[])
{
	if (argc != 3) {
		printf("Too few arguments:\n"
				"Usage: XXX glade-file outfile.h\n"
				);
		exit(1);
	}

	size_t sz;
	char *p = (char *)read_file(&sz, "%s", argv[1]);
	if (!p) {
		printf("Can't read %s\n", argv[1]);
		exit(1);
	}

	std::string in(p);
	std::string out =
			"#pragma once\n"
			"#include <string>\n"
			"\n"
			"std::string glade_file = \n\"";
	out += escape_string_for_c(in);
	out += "\";";

	write_file((void *)out.c_str(), out.size(), "%s", argv[2]);
}
