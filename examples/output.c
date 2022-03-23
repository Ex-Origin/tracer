#include <unistd.h>

int main()
{
    write(STDOUT_FILENO, "h", 1);
    write(STDOUT_FILENO, "e", 1);
    write(STDOUT_FILENO, "l", 1);
    write(STDOUT_FILENO, "l", 1);
    write(STDOUT_FILENO, "o", 1);
    write(STDOUT_FILENO, " ", 1);
    write(STDOUT_FILENO, "w", 1);
    write(STDOUT_FILENO, "o", 1);
    write(STDOUT_FILENO, "r", 1);
    write(STDOUT_FILENO, "l", 1);
    write(STDOUT_FILENO, "d", 1);
    write(STDOUT_FILENO, "\n", 1);
    return 0;
}