#include <sys/types.h>
#include <sys/stat.h>

#include "utils.hh"

unsigned get_number_of_cores()
{
	return 1; // FIXME!
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
