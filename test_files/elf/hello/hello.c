#include <stdio.h>

int sum(int *numbers, int length)
{
    int total = 0;
    for (int i = 0; i < length; i++)
    {
        total += numbers[i];
    }
    return total;
}

int main()
{
    int numbers[] = {1, 2, 3, 4, 5};
    int total = sum(numbers, 5);
    printf("Sum: %d\n", total);
    return 0;
}