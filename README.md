Bandicoot
=========

## Overview

Bandicoot is a crash reporting library that is inspired by the Redis crash reporting system.
This library was extracted from Redis and generalized so that any application can use it.
It is BSD licensed so feel free to customize it and redistribute it.

To use it, simply include the header file and initialize it:

    #include <bandicoot.h>
    
    int main() {
        // Initialize bandicoot at the beginning.
        bandicoot_init();

        // Run your code here!

        return 0;
    }

When your code breaks then you should see a bug report dumped to `STDERR` with a backtrace and register values.


## Contributing

If you find bugs or have features you want to add, please submit a GitHub ticket for them.