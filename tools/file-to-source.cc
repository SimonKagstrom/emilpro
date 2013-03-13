#include <utils.hh>

#include <string>
#include <stdio.h>

int main(int argc, const char *argv[])
{
	if (argc != 4) {
		printf("Too few arguments:\n"
				"Usage: XXX infile outfile.h symbol_name\n"
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
			fmt("#pragma once\n"
			"#include <string>\n"
			"\n"
			"std::string %s = \n\"", argv[3]);
	out += escape_string_for_c(in);
	out += "\";";

	write_file((void *)out.c_str(), out.size(), "%s", argv[2]);
}
