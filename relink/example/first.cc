#include "libs.hh"

#include <stdio.h>

void first_a(void)
{
	printf("In %s\n", __FUNCTION__);
	second_a();
}

void first_b(void)
{
	printf("In %s\n", __FUNCTION__);
	second_b();
}

void __attribute__((constructor)) is_constructor(void)
{
	printf("is_constructor\n");
}
