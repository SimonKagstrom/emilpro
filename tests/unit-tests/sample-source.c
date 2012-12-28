int fn(int a, int b)
{
	int out = a;

	// Branch
	if (a > b)
		out = a / b; // Arithmetic

	return out;
}

int second(int a)
{
	// Function call
	return fn(a, 3);
}
