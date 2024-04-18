#include "stdio.h"

int fn(int a, int b)
{
    printf("I am within library 3\n");
    printf("Within the function: %s, I will perform addition of two numbers\n", __func__);
	return (a+b);
}
