ZX Spectrum snapshot tracer
===========================

This utility attempts to locate code regions in 48K Spectrum snapshots.
It uses static tracing to follow all possible code paths.


Compiling
---------

The code should build under most Unix-like platforms.

Required libraries:
  libspectrum: http://fuse-emulator.sf.net/libspectrum.php
  libpng: http://www.libpng.org/pub/png/libpng.html

If your headers and libraries are in standard locations, simply use:
  g++ -o snaptrace snaptrace.cpp -lspectrum -lpng

Or if you have the CMake build system installed, use:
  mkdir build
  cd build
  cmake ..
  make


Running
-------

  Usage: %s [-v] [-u] [-2] [-r] [-s] <snapshot>

    -v   Verbose output with more detail about tracing
    -vv  Extra verbose output for every location visited
    -u   Force scanning for USR statements to trace
    -2   Skip IM2 handler tracing, even if in IM2
    -r   Include ROM area in output image (256x256)
    -s   Don't save results to PNG image

    <snapshot> should be a 48K snapshot in SZX/Z80/SNA/SNP format.

For the default settings simply pass the snapshot file on the command-line:

  ./snaptrace manic.z80

This traces code from the PC value in the snapshot.  If this fails to reach
any RAM the program searches for USR expressions to use as entry points.  If
the snapshot indicates interrupt mode 2, the interrupt handler is traced.

After a successful trace the program reports the number of code bytes.  The
locations are written to a PNG image, using the same base filename as the
snapshot.  Each pixel in the image represents 1 byte in RAM, with colours
indicating how code was reached:

  green = code found from snapshot Program Counter
  red = code found from USR statement in BASIC listing
  blue = code found from IM 2 handler

If the same location was visited from different starting points, the colours
are combined using additive mixing (i.e. green+red=yellow).


Output
------

Information:

 "return address data access"
   The return address was popped and data read from that location.

 "return address popped"
   The return address was popped but with no recognised data access.
   This may simply be to discard one or more calls, preventing a return,
   or could require additional handling to be recognised.

 "data following call to XXXX"
   The call to XXXX is followed by data, and further calls to it blacklisted.

 "ret to stacked data"
   Data was on the stack when a RET was encountered.
   This may simply be to insert a new exit point before the original return.

 "ex (sp) on return address"
   Program is accessing the return address on the stack using EX (SP),HL/IX/IY
   This is only a notification of likely mixed code/data use.

Warnings:

 "*** suspicious block of 4+ NOPs ***"
   A block of 4 or more NOPs have been encountered during the trace process.
   Tracing has likely escaped into unused memory!

 "*** suspicious ld r,r ***"
   An inert assignment with the same source and target register has been.
   Tracing has likely escaped and executing data!

The last 2 messages may indicate a problem in snaptrace, which needs fixing.
If you encounter either of them, please send me the snapshot(s) for analysis.


Credits
-------

Spectrum 48K ROM is copyright (c) Amstrad Consumer Electronics plc.
Amstrad have kindly given their permission for the redistribution of their
copyrighted material but retain that copyright.

---

Simon Owen
http://simonowen.com/
