#include <stdio.h>
#include <unistd.h>

int main()
{
    printf("uid: %d\n", getuid());
    return 0;
}