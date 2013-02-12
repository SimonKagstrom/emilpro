#include <stdint.h>

uint32_t global_data_bss;

uint32_t global_data = 5;

extern "C" void kalle(void)
{
	global_data = 2;
}

int main(int argc, const char *argv[])
{
	kalle();

	return 0;
}

extern "C" void knatte(void)
{
	kalle();
}
