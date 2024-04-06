#pragma once

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#include <string>
#include <list>

#define error(x...) do \
{ \
	printf("Error: "); \
	printf(x); \
	printf("\n"); \
} while(0)

#define warning(x...) do \
{ \
	printf("Warning: "); \
	printf(x); \
	printf("\n"); \
} while(0)

#define panic(x...) do \
{ \
	error(x); \
	exit(1); \
} while(0)

enum debug_mask
{
	INFO_MSG   = 1,
	ENGINE_MSG = 2,
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

static inline void *xrealloc(void *p, size_t sz)
{
  void *out = realloc(p, sz);

  panic_if(!out, "realloc failed");

  return out;
}

unsigned get_number_of_cores();

void *read_file(size_t *out_size, const char *fmt, ...);

void *read_file_timeout(size_t *out_size, uint64_t timeout_ms, const char *fmt, ...);

int write_file_timeout(const void *data, size_t len, uint64_t timeout_ms, const char *fmt, ...);

int write_file(const void *data, size_t len, const char *fmt, ...);

std::string fmt(const char *fmt, ...) __attribute__((format(printf,1,2)));

std::string escapeHtml(std::string &str);

std::string escapeHtml(const char *str);

bool cpu_is_little_endian();

std::string trimString(std::string &strIn);

std::string get_home_directory();

bool string_is_integer(std::string str, unsigned base = 0);

int64_t string_to_integer(std::string str, unsigned base = 0);

std::string escape_string_for_c(std::string &str);

std::string escape_string_for_xml(const std::string &str);

std::string unescape_string_from_xml(const std::string &str);

std::string scrub_html(const std::string &str);

uint64_t get_utc_timestamp();

void adjust_utc_timestamp(int64_t diff);

void msleep(uint64_t ms);


// Unit test stuff
void mock_read_file(void *(*callback)(size_t *out_size, const char *path));

void mock_write_file(int (*callback)(const void *data, size_t size, const char *path));


void mock_utc_timestamp(uint64_t ts);

std::list<std::string> split_string(const std::string &s, const char *delims);
