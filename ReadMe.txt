ZX Spectrum snapshot tracer
===========================

This utility attempts to locate code regions in 48K Spectrum snapshots.
It uses static tracing to follow all possible code paths, without executing
any code or modifying the snapshot memory.


Compiling
---------

The code should build under most Unix-like platforms.

Required libraries:
  libspectrum: http://fuse-emulator.sf.net/libspectrum.php
  libpng: http://www.libpng.org/pub/png/libpng.html

If you're using Ubuntu that may be as simple as:
  sudo apt-get install libspectrum-dev libpng12-dev

If your headers and libraries are in standard locations, use:
  g++ -o snaptrace snaptrace.cpp -lspectrum -lpng

Or if you have the CMake build system installed, use:
  mkdir build
  cd build
  cmake ..
  make
  sudo make install


Running
-------

  Usage: snaptrace [-bcdimrsvz] <snapshot>

    -b   Skip scanning BASIC for USR code entry points
    -c   Continue trace beyond suspicious code
    -d   Show addresses in decimal rather than hex
    -i   Skip tracing IM 2 handler, even if in IM 2 mode
    -m   Save code bitmap to .map file
    -r   Include ROM area in trace output files
    -s   Don't save results to .png image
    -v   Increase verbosity (0=basic, 1=control, 2=stack, 3=instructions)
    -z   Include only Z80 instruction start in .map file

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
  white = BASIC program

If the same location was visited from different starting points, the colours
are combined using additive mixing (i.e. green+red=yellow).

For the best results use a snapshot saved at the main game menu.  Some games
perform runtime code manipulation during startup, which can't be traced.


Output
------

Information:

 "return address data access"
   The return address was popped and data read from that location.

 "return address popped"
   The return address was popped but with no recognised data access.
   This may simply be to discard one or more calls, preventing a return,
   or could require additional handling to be recognised.

 "RET to stacked data"
   Data was on the stack when a RET was encountered.
   This may simply be to insert a new exit point before the original return.

 "stopping at EX (SP) on return address"
   Program is accessing the return address on the stack using EX (SP),HL/IX/IY
   This is only a notification of likely mixed code/data use.

 "stopping at ROM loader"
   Calls following calls to the Spectrum tape loading code rely on loaded
   data, so tracing cannot safely continue beyond it.

 "blacklisted call to XXXX"
   Code at the indicated address is accessing data at the return address
   location.  Tracing is prevented from returning to the calling location.

 "skipped due to suspicious code start"
   The start of an entry point doesn't look like code and will not be traced.

Warnings:

 "*** suspicious block of X NOPs ***"
   A large block of X NOPs have been encountered during the trace process.
   Tracing has likely escaped into open/unused memory!

 "*** suspicious LD r,r ***"
   An inert assignment with the same source and target register was found.
   Tracing has likely escaped and is executing data!

The last 2 messages may indicate a problem in snaptrace that needs fixing.
If you encounter either of them, please send me the snapshot(s) for analysis.


Credits
-------

Special thanks to Richard Dymond for helping with problem cases.

Spectrum 48K ROM is copyright (c) Amstrad Consumer Electronics plc.
Amstrad have kindly given their permission for the redistribution of their
copyrighted material but retain that copyright.

---

Simon Owen
http://simonowen.com/
