#include <stdio.h>
#include "bandicoot.h"

int runBadCode()
{
    int *ptr = NULL;
    printf("Executing bad code.\n");
    return (*ptr)+1;
}

int main()
{
    printf("Initializing Bandicoot.\n");
    
    // Initialize the error reporting.
    bandicoot_init();
    
    printf("Calling bad function.\n");

    // Call function.
    runBadCode();
    
    return 0;
}