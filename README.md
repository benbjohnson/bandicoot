Bandicoot
=========

Bandicoot is a crash reporting library that is inspired by the Redis crash reporting system.
To use it, simply include the header file and initialize it:

    #include <bandicoot.h>
    bandicoot_init();

When your code breaks then you should see a bug report dumped to `STDERR` with a backtrace and register values.

