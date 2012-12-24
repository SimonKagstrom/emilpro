int global_data;

extern "C" void kalle(void)
{
	global_data = 2;
}

int main(int argc, const char *argv[])
{
	kalle();

	return 0;
}
