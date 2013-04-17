#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdexcept>
#include <time.h>

#include "utils.hh"

static void* (*mocked_read_callback)(size_t* out_size, const char* path);
static int (*mocked_write_callback)(const void* data, size_t size, const char* path);


unsigned get_number_of_cores()
{
	return 1; // FIXME!
}

bool cpu_is_little_endian()
{
	static uint16_t data = 0x1122;
	uint8_t *p = (uint8_t *)&data;

	return p[0] == 0x22;
}


void *read_file(size_t *out_size, const char *fmt, ...)
{
	struct stat buf;
	char path[2048];
	va_list ap;
	void *data;
	size_t size;
	FILE *f;
	int r;

	/* Create the filename */
	va_start(ap, fmt);
	r = vsnprintf(path, 2048, fmt, ap);
	va_end(ap);

	panic_if (r >= 2048,
			"Too long string!");

	if (mocked_read_callback)
		return mocked_read_callback(out_size, path);

	if (lstat(path, &buf) < 0)
		return NULL;

	size = buf.st_size;
	data = xmalloc(size + 2); /* NULL-terminate, if used as string */
	f = fopen(path, "r");
	if (!f)
	{
		free(data);
		return NULL;
	}
	if (fread(data, 1, size, f) != size)
	{
		free(data);
		data = NULL;
	}
	fclose(f);

	*out_size = size;

	return data;
}

int write_file(const void *data, size_t len, const char *fmt, ...)
{
	char path[2048];
	va_list ap;
	FILE *fp;
	int ret = 0;

	/* Create the filename */
	va_start(ap, fmt);
	vsnprintf(path, 2048, fmt, ap);
	va_end(ap);

	if (mocked_write_callback)
		return mocked_write_callback(data, len, path);

	fp = fopen(path, "w");
	if (!fp)
		return -1;

	if (fwrite(data, sizeof(uint8_t), len, fp) != len)
		ret = -1;
	fclose(fp);

	return ret;
}

std::string fmt(const char *fmt, ...)
{
	char buf[4096];
	va_list ap;
	int res;

	va_start(ap, fmt);
	res = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	panic_if(res >= (int)sizeof(buf),
			"Buffer overflow");

	return std::string(buf);
}

char *escapeHelper(char *dst, const char *what)
{
	int len = strlen(what);

	strcpy(dst, what);

	return dst + len;
}

std::string escapeHtml(std::string &str)
{
	const char *s = str.c_str();
	char buf[4096];
	char *dst = buf;
	size_t len = strlen(s);
	size_t i;

	memset(buf, 0, sizeof(buf));
	for (i = 0; i < len; i++) {
		char c = s[i];

		switch (c) {
		case '<':
			dst = escapeHelper(dst, "&lt;");
			break;
		case '>':
			dst = escapeHelper(dst, "&gt;");
			break;
		case '&':
			dst = escapeHelper(dst, "&amp;");
			break;
		case '\"':
			dst = escapeHelper(dst, "&quot;");
			break;
		case '\'':
			dst = escapeHelper(dst, "&#039;");
			break;
		case '/':
			dst = escapeHelper(dst, "&#047;");
			break;
		case '\\':
			dst = escapeHelper(dst, "&#092;");
			break;
		case '\n': case '\r':
			dst = escapeHelper(dst, " ");
			break;
		default:
			*dst = c;
			dst++;
			break;
		}
	}

	return std::string(buf);
}

std::string escapeHtml(const char *str)
{
	std::string s = str;

	return escapeHtml(s);
}

std::string trimString(std::string &strIn)
{
	std::string str = strIn;
	size_t endpos = str.find_last_not_of(" \t");

	if( std::string::npos != endpos )
	{
		str = str.substr( 0, endpos+1 );
	}

	// trim leading spaces
	size_t startpos = str.find_first_not_of(" \t");
	if( std::string::npos != startpos )
	{
		str = str.substr( startpos );
	}

	return str;
}

std::string get_home_directory()
{
	// FIXME! This will not work in Windows, if someone would like to use that
	std::string home = getenv("HOME");

	return home;
}

bool string_is_integer(std::string str)
{
	size_t pos;

	try
	{
		stoll(str, &pos, 0);
	}
	catch(std::invalid_argument &e)
	{
		return false;
	}

	return pos == str.size();
}

int64_t string_to_integer(std::string str)
{
	size_t pos;

	return (int64_t)stoll(str, &pos, 0);
}

std::string escape_string_for_c(std::string &str)
{
	std::string out;

	for (unsigned i = 0; i < str.size(); i++) {
		char c = str[i];

		if (c == '"')
			out += '\\';
		if (c == '\n')
			out += "\\n\"\n\"";
		else
			out += c;
	}

	return out;
}

std::string escape_string_for_xml(std::string &str)
{
	std::string out;

	for (unsigned i = 0; i < str.size(); i++) {
		char c = str[i];

		if (c == '<')
			out += "\\<";
		if (c == '>')
			out += "\\>";
		else
			out += c;
	}

	return out;
}

uint64_t get_utc_timestamp()
{
	time_t raw;
	struct tm *ptm;
	struct tm tmp;

	time(&raw);
	ptm = gmtime_r(&raw, &tmp);

	if (ptm == NULL)
		return 0;

	return (uint64_t)timegm(ptm);
}


void mock_read_file(void* (*callback)(size_t* out_size, const char* path))
{
	mocked_read_callback = callback;
}

void mock_write_file(int (*callback)(const void* data, size_t size, const char* path))
{
	mocked_write_callback = callback;
}
