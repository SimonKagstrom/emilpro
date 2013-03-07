#pragma once

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#include <string>

#define error(x...) do \
{ \
	fprintf(stderr, "Error: "); \
	fprintf(stderr, x); \
	fprintf(stderr, "\n"); \
} while(0)

#define warning(x...) do \
{ \
	fprintf(stderr, "Warning: "); \
	fprintf(stderr, x); \
	fprintf(stderr, "\n"); \
} while(0)

#define panic(x...) do \
{ \
	error(x); \
	exit(1); \
} while(0)

enum debug_mask
{
	INFO_MSG   = 1,
	PTRACE_MSG = 2,
	ELF_MSG    = 4,
	BP_MSG     = 8,
};
extern int g_coin_debug_mask;

static inline void coin_debug(enum debug_mask dbg, const char *fmt, ...) __attribute__((format(printf,2,3)));

static inline void coin_debug(enum debug_mask dbg, const char *fmt, ...)
{
	va_list ap;

	if ((g_coin_debug_mask & dbg) == 0)
		return;

	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
}

#define panic_if(cond, x...) \
		do { if ((cond)) panic(x); } while(0)

static inline char *xstrdup(const char *s)
{
	char *out = strdup(s);

	panic_if(!out, "strdup failed");

	return out;
}

static inline void *xmalloc(size_t sz)
{
  void *out = malloc(sz);

  panic_if(!out, "malloc failed");
  memset(out, 0, sz);

  return out;
}

unsigned get_number_of_cores();

void *read_file(size_t *out_size, const char *fmt, ...);

int write_file(const void *data, size_t len, const char *fmt, ...);

std::string fmt(const char *fmt, ...);

std::string escapeHtml(std::string &str);

std::string escapeHtml(const char *str);

bool cpu_is_little_endian();

std::string trimString(std::string &strIn);

std::string get_home_directory();
