// ZX Spectrum 48K snapshot code tracer, by Simon Owen <simon@simonowen.com>

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <png.h>
#include "libspectrum.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#else
#define ROM_DIR
#endif

#define MAX_NOP_RUN 10  // Allow up to 10 NOPs before we suspect we're in free memory

#define MARK_INSTR 0x08 // seen[] bit indicating start of z80 instruction

#define PROG   0x5c53   // contains address of BASIC program
#define VARS   0x5c4b   // contains address of BASIC variables
#define E_LINE 0x5c59   // contains address being typed in
#define STKEND 0x5c65   // contains start address of spare space

typedef unsigned char BYTE;
typedef unsigned short WORD;

// trace_addr return conditions
enum { retOK=0x00, retBlacklist=0x01 };

WORD reg_pc, reg_sp;    // PC and SP from snapshot
BYTE reg_i, reg_im;     // I and interrupt mode from snapshot

BYTE poss_i, poss_im;   // possible I and IM values in the code

BYTE mem[0x10000];      // 64K address space, first 16K ROM
BYTE seen[0x10000];     // code locations visited
BYTE blacklist[0x10000];// blacklisted calls due to stack manipulation
BYTE mark;              // current marker colour bit to combine into seen[pc]
int basiclen;           // count of bytes in BASIC listing

int savemsb = 0x40;     // 0x40 to save 48K RAM, 0x00 to save full 64K
int verbose = 0;        // 0-2 for tracing detail levels
bool basictrace = true; // trace USR statements found in BASIC (enabled, -b to disable)
bool im2trace = true;   // trace interrupt handler if IM 2 active (enabled, -i to disable)
bool pngsave = true;    // save output as PNG image (enabled, -s to disable)
bool mapsave = false;   // save code bitmap (disabled, -m to enable)
bool instrmap = false;  // only include z80 instruction start in map (disabled, -z to enable)
bool decaddr = false;   // output addresses in decimal (disabled, -d to enable)


const char *AddrStr (WORD addr)
{
    static char strs[4][16];
    static int cur;

    // Write address string to next buffer in current base
    cur = (cur+1) & 3;
    snprintf(strs[cur], sizeof(strs[cur]), decaddr ? "%05u" : "%04X", addr);

    return strs[cur];
}

void Log (int level, int pc, const char *fmt, ...)
{
    // Optionally output PC
    if (pc >= 0) printf("%s: ", AddrStr(pc));

    // Output indent
    printf("%*s", (verbose > 0) ? (3*level) : 0, "");

    // Output rest of message
    va_list args;
    va_start (args, fmt);
    vprintf(fmt, args);
    va_end(args);
}


int trace_addr (WORD pc, WORD sp, WORD basesp, int level)
{
    WORD pc0, addr;
    BYTE op;
    bool ddfd = false;
    int ret = retOK;

    // Continuing beyond ROM loader is unsafe as it may rely on loaded code
    if (pc == 0x0556)
    {
        Log(level, pc, "stopping at ROM loader\n");
        return retBlacklist;
    }

    // Loop until we reach an instruction location using the current mark
    while ((seen[pc] & (MARK_INSTR|mark)) != (MARK_INSTR|mark))
    {
        if (verbose > 2 && !ddfd) Log(0, -1, "PC=%s SP=%s stacked=%d %s\n", AddrStr(pc), AddrStr(sp), int(basesp)-sp, (level==0)?"top-level":"");

        // Start of instruction, 1 byte back if there's an index prefix
        pc0 = pc - ddfd;

        // Next instruction (or prefix), mark as visited
        op = mem[pc];
        seen[pc++] |= (MARK_INSTR|mark);

        switch (op)
        {
            case 0xdd: case 0xfd: // index prefix
                ddfd = true;
                continue;

            case 0xcb: // CB extended set
                if (ddfd) seen[pc++] |= mark;
                seen[pc++] |= mark;
                break;

            case 0xed: // ED extended set
                op = mem[pc];
                seen[pc++] |= mark;

                switch (op)
                {
                    case 0x45: case 0x55: case 0x65: case 0x75: // retn
                    case 0x4d: case 0x5d: case 0x6d: case 0x7d: // reti

                        // Fetch return address from top of stack
                        addr = (mem[sp+1] << 8) | mem[sp];
                        if (verbose) Log(level, pc0, "RETI/RETN to %s %s\n", AddrStr(addr), (level==0)?"(top-level)":"");

                        // Top-level is a special case and treated as a new entry point
                        if (level == 0)
                            return trace_addr(addr, sp+2, sp+2, 0);

                        // Stopping at RETN/RETI
                        return ret;

                    case 0x7b: // ld sp,(nn)
                        addr = (mem[pc0+2] << 8) | mem[pc0+1];
                        if (verbose > 1) Log(level, pc0, "LD SP,(%s)\n", AddrStr(addr));
                        basesp = sp;
                    case 0x43: case 0x53: case 0x63: case 0x73: // ld (nn),rr
                    case 0x4b: case 0x5b: case 0x6b: // ld rr,(nn)
                        seen[pc++] |= mark;
                        seen[pc++] |= mark;
                        break;

                    case 0x47: // ld i,a
                        if (mem[pc0-2] == 0x3e/*ld a,n*/ && mem[pc0-1] > 0x40)
                        {
                            poss_i = mem[pc0-1];
                            if (verbose > 1) Log(level, pc0-2, "LD A,%02X ; LD I,A\n", poss_i);
                        }
                        break;

                    case 0x5e: // im 2
                        if (verbose > 1) Log(level, pc0, "IM 2\n");
                        poss_im = 2;
                        break;
                }
                break;


            case 0x00: // nop
                if (pc0 >= 0x4000 && pc0 < (0xffff-MAX_NOP_RUN) && !memcmp(mem+pc0, mem+pc0+1, MAX_NOP_RUN-1))
                {
                    Log(level, pc0, "*** suspicious block of %d+ NOPs ***\n", MAX_NOP_RUN);
                    return ret;
                }
                break;

            case 0xe3: // ex (sp),hl/ix/iy
                if (verbose > 1) Log(level, pc0, "EX (SP),%s\n", ddfd?"IX/IY":"HL");

                if (sp == basesp) // pointing to return adddress?
                {
                    if (pc >= 0x4000) Log(level, pc0, "stopping at EX (SP) on return address\n");
                    return retBlacklist;
                }
                break;

            case 0x34: case 0x35:   // inc/dec (ix+d)
            case 0x46: case 0x4e: case 0x56: case 0x5e: case 0x66: case 0x6e: case 0x7e: // ld r,(ix+d)
            case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75: case 0x77: // ld (ix+d),r
            case 0x86: case 0x8e: case 0x96: case 0x9e: case 0xa6: case 0xae: case 0xb6: case 0xbe: // add/adc/sub/sbc/and/xor/or/cp (ix+d)
                if (ddfd) seen[pc++] |= mark;
                break;

            case 0x36: // ld (hl),n ; ld (ix+d),n
                if (ddfd) seen[pc++] |= mark;
                seen[pc++] |= mark;
                break;

            case 0x10: // djnz
            case 0x18: // jr
            case 0x20: case 0x28: case 0x30: case 0x38: // jr cc
            {
                seen[pc++] |= mark;

                addr = pc0+2+static_cast<signed char>(mem[pc0+1]);
                if (verbose) Log(level, pc0, "%s %s\n", (op==0x10)?"DJNZ":"JR", AddrStr(addr));

                // Trace the jump target
                ret |= trace_addr(addr, sp, basesp, level);

                // Unconditional JR stops here
                if (op == 0x18)
                    return ret;

                // Continue processing after JR cc or DJNZ
                break;
            }

            case 0xc3: // jp
            case 0xc2: case 0xca: case 0xd2: case 0xda: case 0xe2: case 0xea: case 0xf2: case 0xfa: // jp cc
            {
                seen[pc++] |= mark;
                seen[pc++] |= mark;

                addr = (mem[pc0+2] << 8) | mem[pc0+1];
                if (verbose) Log(level, pc0, "JP %s\n", AddrStr(addr));

                // Trace the jump target
                ret |= trace_addr(addr, sp, basesp, level);

                // Unconditional JP stops here
                if (op == 0xc3)
                    return ret;

                // Continue processing after JP cc
                break;
            }

            case 0xcd: // call
            case 0xc4: case 0xcc: case 0xd4: case 0xdc: case 0xe4: case 0xec: case 0xf4: case 0xfc: // call cc
            case 0xc7: case 0xcf: case 0xd7: case 0xdf: case 0xe7: case 0xef: case 0xf7: case 0xff: // rst

                if ((op & 0xc7) == 0xc7) // rst?
                {
                    addr = op & 0x38;
                    if (verbose) Log(level, pc0, "RST %02X\n", addr);
                }
                else // call
                {
                    seen[pc++] |= mark;
                    seen[pc++] |= mark;

                    addr = (mem[pc0+2] << 8) | mem[pc0+1];
                    if (verbose) Log(level, pc0, "CALL %s\n", AddrStr(addr));
                }

                // If the call address is blacklisted, stop here
                if (blacklist[addr])
                    return ret;

                // Trace the call target
                ret |= trace_addr(addr, sp-2, sp-2, level+1);

                // Should the call we just made be blacklisted?
                if (ret & retBlacklist)
                {
                    if (pc >= 0x4000) Log(level, pc0, "blacklisted calls to %s\n", AddrStr(addr));
                    blacklist[addr] = 1;
                    return ret & ~retBlacklist;
                }

                // Continue processing after CALL
                break;

            case 0xc9: // ret
            case 0xc0: case 0xc8: case 0xd0: case 0xd8: case 0xe0: case 0xe8: case 0xf0: case 0xf8: // ret cc

                // Fetch return address from top of stack
                addr = (mem[sp+1] << 8) | mem[sp];

                if (pc0 >= 0x4000 && sp < basesp)
                    Log(level, pc0, "RET to stacked data\n");
                else if (level == 0)
                {
                    // Top-level is a special case and treated as a new entry point
                    if (verbose) Log(level, pc0, "RET to %s %s\n", AddrStr(addr), (level==0)?"(top-level)":"");
                    return trace_addr(addr, sp+2, sp+2, 0);
                }

                // Unconditional RET stops here
                if (op == 0xc9)
                    return ret;

                // Continue processing after RET cc
                break;

            case 0xe9: // jp (hl)
                return ret;


            case 0xc5: case 0xd5: case 0xe5: case 0xf5: // push rr
                if (verbose > 1) Log(level, pc0, "PUSH\n");
                sp -= 2;
                break;

            case 0xc1: case 0xd1: case 0xe1: case 0xf1: // pop rr
                if (verbose > 1) Log(level, pc0, "POP\n");

                // Pop with no data on the stack? (not top-level as stack state is unknown)
                if (sp == basesp && level > 0)
                {
                    // Return pop followed by data access?
                    if (!ddfd &&
                        ((op == 0xe1 && (mem[pc] & 0xc7) == 0x46) || // pop hl ; ld r,(hl)
                         (op == 0xd1 &&  mem[pc]         == 0x1a) || // pop de ; ld a,(de)
                         (op == 0xc1 &&  mem[pc]         == 0x0a)))  // pop bc ; ld a,(bc)
                    {
                        if (pc >= 0x4000) Log(level, pc, "return address data access\n");
                        ret |= retBlacklist;
                    }
                    else if (ddfd && op == 0xe1) // pop ix/iy
                    {
                        for (WORD w = 0 ; w < 10 ; w++) // access must be within ~10 bytes
                        {
                            if (mem[pc+w] == mem[pc0] && (mem[pc+w+1] & 0xc7) == 0x46 && mem[pc+w+2] <= 0x01) // ld r,(ix/iy+0/1)
                            {
                                if (pc >= 0x4000) Log(level, pc+w, "return address data access\n");
                                ret |= retBlacklist;
                            }
                        }
                    }

                    // Report the return address pop unless we've detected a data access
                    if (!(ret & retBlacklist) && pc >= 0x4000) Log(level, pc-1-ddfd, "return address popped\n");
                }

                sp += 2;
                if (level == 0) basesp = sp;
                break;

            case 0x33:  // inc sp
                if (verbose > 1) Log(level, pc0, "INC SP\n");
                sp++;
                break;

            case 0x3b:  // dec sp
                if (verbose > 1) Log(level, pc0, "DEC SP\n");
                sp--;
                break;


            case 0x06: case 0x0e: case 0x16: case 0x1e: case 0x26: case 0x2e: case 0x3e: // ld r,n
            case 0xc6: case 0xce: case 0xd6: case 0xde: case 0xe6: case 0xee: case 0xf6: case 0xfe: // add/adc/sub/sbc/and/xor/or/cp n
            case 0xd3: case 0xdb: // out (n),a ; in a,(n)
                seen[pc++] |= mark;
                break;

            case 0x31:  // ld sp,nn
                addr = (mem[pc0+2] << 8) | mem[pc0+1];
                if (verbose > 1) Log(level, pc0, "LD SP,%s\n", AddrStr(addr));
                basesp = sp;
            case 0x01: case 0x11: case 0x21: // ld rr,nn
            case 0x22: case 0x2a: case 0x32: case 0x3a: // ld (nn),hl ; ld hl,(nn) ; ld (nn),a ; ld a,(nn)
                seen[pc++] |= mark;
                seen[pc++] |= mark;
                break;

            case 0x40: case 0x49: case 0x52: case 0x5b: case 0x64: case 0x6d: case 0x7f: // ld r,r
                Log(level, pc0, "*** suspicious ld r,r ***\n");
                return ret;
        }

        ddfd = false;
    }

    return ret;
}

// Trace a given address, if it looks safe to do
void trace_safe (WORD pc, WORD sp)
{
    if (mem[pc] == 0x00 || mem[pc] == 0xff)
        printf("skipped due to suspicious code start (%02X)\n", mem[pc]);
    else
        trace_addr(pc, sp, sp, 1); // not top-level, no return allowed
}


void trace_line (WORD addr, int len, int line)
{
    int i;
    bool inquotes = false;

    if (verbose && line >= 0)
        Log(0, addr, "BASIC line %u len %u\n", line, len);

    for (i = addr ; i < addr+len ; i++)
    {
        // REMs can contain almost anything, including code, so just skip them
        if (mem[i] == 0xea)
        {
            if (verbose) printf(" skipping REM (%u bytes)\n", len-(i-addr)-1);
            i = addr+len-1;
            break;
        }

        // Track strings, so UDGs can be ignored
        if (mem[i] == '"')
        {
            inquotes = !inquotes;
            continue;
        }

        if (inquotes)
            continue;

        // Return or end marker?
        else if (mem[i] == 0x0d || mem[i] == 0x80)
            break;

        // 5-byte number format?
        else if (mem[i] == 0x0e)
        {
            i += 5;
            continue;
        }
        // Continue search for anything but USR
        else if (mem[i] != 0xc0)
            continue;

        // VAL$ with string?
        if (mem[i+1] == 0xb0 && mem[i+2] == '"')
        {
            WORD addr = 0;

            // Convert string digits to number
            for (i+=3 ; isdigit(mem[i]) ; i++)
                addr = addr*10 + mem[i]-'0';

            // Check for end of string
            if (mem[i] == '"')
            {
                if (line < 0)
                    printf("Found USR VAL$ %s on edit line\n", AddrStr(addr));
                else
                    printf("Found USR VAL$ %s on line %u\n", AddrStr(addr), line);

                mark = 2; // red
                trace_safe(addr, reg_sp);
            }
        }
        else if (isdigit(mem[i+1]))
        {
            WORD textaddr = 0;

            // Convert string digits to number, to check against encoded number
            for (i++ ; isdigit(mem[i]) ; i++)
                textaddr = textaddr*10 + mem[i]-'0';

            // 5-byte number format with an integer?
            if (mem[i] == 0x0e && mem[i+1] == 0 && mem[i+2] == 0 && mem[i+5] == 0)
            {
                WORD addr = (mem[i+4] << 8) | mem[i+3];
                if (line < 0)
                    printf("Found USR %s on edit line\n", AddrStr(addr));
                else if (textaddr != addr)
                    printf("Found USR %s [\"%s\"] on line %u\n", AddrStr(addr), AddrStr(textaddr), line);
                else
                    printf("Found USR %s on line %u\n", AddrStr(addr), line);

                mark = 2; // red
                trace_safe(addr, reg_sp);

                // Step back so the number token is seen and skipped
                i--;
            }
        }
    }

    // Include the 4-byte header on normal program lines
    if (line >= 0) addr -= 4;
    basiclen += i-addr+1;

    // Mark the BASIC program in whitee
    mark = 7; // white
    while (addr <= i)
        seen[addr++] |= mark;
}

void trace_prog ()
{
    // Look up BASIC program and variables addresses
    WORD prog = (mem[PROG+1] << 8) | mem[PROG];
    WORD vars = (mem[VARS+1] << 8) | mem[VARS];

    // Check the values are sensible before we use them (terminator before prog, CR before vars)
    if (prog && vars && (vars > prog) && mem[prog-1] == 0x80 && mem[vars-1] == 0x0d)
    {
        while (mem[prog] < 0x40 && prog < vars)
        {
            WORD line = (mem[prog] << 8) | mem[prog+1];
            WORD len = (mem[prog+3] << 8) | mem[prog+2];
            prog += 4;

            // Stop if the line length exceeds the program area
            if (prog+len > vars)
                break;

            // Trace USRs on the line
            trace_line(prog, len, line);

            // Advance to next line
            prog += len;
        }
    }
}

void trace_eline ()
{
    // Look up edit line and spare space addresses
    WORD e_line = (mem[E_LINE+1] << 8) | mem[E_LINE];
    WORD stkend = (mem[STKEND+1] << 8) | mem[STKEND];

    // Check the values are sensible before we use them (terminators before each)
    if (e_line && stkend && (stkend > e_line) && mem[e_line-1] == 0x80 && mem[stkend-1] == 0x80)
        trace_line(e_line, stkend-e_line, -1);
}


void trace_im2 (BYTE i)
{
    WORD im_table = (i << 8) | 0x00;
    WORD im_addr = (mem[im_table+255] << 8) | mem[im_table+256];

    // Sanity check to support runtime IM 2 detection
    if (i >= 0x40 && im_addr >= 0x4000 && (im_addr >> 8) == (im_addr & 0xff))
    {
        printf("Tracing IM 2 from %s\n", AddrStr(im_addr));

        mark = 1; // blue
        trace_safe(im_addr, reg_sp);
    }
}


bool read_rom (const char *romfile)
{
    FILE *f = fopen(romfile, "rb");
    size_t datalen = 0;

    if (f)
    {
        datalen = fread(mem, 1, 0x4000, f);
        fclose(f);
    }

    return f != NULL && datalen == 0x4000;
}

int read_snapshot (const char *filename)
{
    bool ret = false;

    libspectrum_snap *snap = libspectrum_snap_alloc();
    if (!snap)
        fprintf(stderr, "libspectrum_snap_alloc() failed\n");
    else
    {
        FILE *f = fopen(filename, "rb");
        if (f)
        {
            unsigned char buf[0x100000];
            size_t len = fread(buf, 1, sizeof(buf), f);
            fclose(f);

            int error = libspectrum_snap_read(snap, buf, len, LIBSPECTRUM_ID_UNKNOWN, filename);
            if (!error)
            {
                // Extract machine details from the snapshot
                libspectrum_machine machine = libspectrum_snap_machine(snap);
                int caps = libspectrum_machine_capabilities(machine);
                libspectrum_byte paging128k = libspectrum_snap_out_128_memoryport(snap);
                libspectrum_byte pagingplus3 = libspectrum_snap_out_plus3_memoryport(snap);

                // Determine conditions related to 48K compatibility
                bool is48k = (machine == LIBSPECTRUM_MACHINE_48);
                bool is128k = (caps & LIBSPECTRUM_MACHINE_CAPABILITY_128_MEMORY) != 0;
                bool isplus2a3 = (caps & LIBSPECTRUM_MACHINE_CAPABILITY_PLUS3_MEMORY) != 0;
                bool is128kas48k = (paging128k & 0x17) == 0x10;
                bool isplus3as48k = (pagingplus3 & 0x01) == 0;

                // 48K, or 128K with 48K paging, and if it's a +2A/+3 it must be normal paging mode
                if (is48k || (is128k && is128kas48k && (!isplus2a3 && isplus3as48k)))
                {
                    // Read 48K RAM banks
                    memcpy(mem+0x4000, libspectrum_snap_pages(snap, 5), 0x4000);
                    memcpy(mem+0x8000, libspectrum_snap_pages(snap, 2), 0x4000);
                    memcpy(mem+0xc000, libspectrum_snap_pages(snap, 0), 0x4000);

                    reg_pc = libspectrum_snap_pc(snap);
                    reg_sp = libspectrum_snap_sp(snap);
                    reg_i = libspectrum_snap_i(snap);
                    reg_im = libspectrum_snap_im(snap);
                    printf("%s: PC=%s SP=%s I=%02X IM=%u\n", filename, AddrStr(reg_pc), AddrStr(reg_sp), reg_i, reg_im);

                    ret = true;
                }
                else
                    fprintf(stderr, "%s: Not a 48K snapshot!\n", filename);
            }
        }
        else
            perror(filename);

        libspectrum_snap_free(snap);
    }

    return ret;
}

void write_png (const char *filename)
{
    char buf[256];
    strncpy(buf, filename, sizeof(buf)-4);

    // Change any file extension for .png
    char *p = strrchr(buf, '.');
    if (p) *p = '\0';
    strcat(buf, ".png");

    FILE *f = fopen(buf, "wb");
    if (f)
    {
        png_structp png = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
        png_infop info = png_create_info_struct(png);
        png_init_io(png, f);

        png_set_IHDR(png, info, 256, 256-savemsb, 8, PNG_COLOR_TYPE_PALETTE, PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_BASE, PNG_FILTER_TYPE_BASE);

        png_color palette[256] = {
            {0,0,0}, {0,0,224}, {224,0,0}, {224,0,224}, {0,224,0}, {0,224,224}, {224,224,0}, {224,224,224},
            {0,0,0}, {64,64,255}, {255,64,64}, {255,64,255}, {64,255,64}, {64,255,255}, {255,255,64}, {255,255,255}
        };
        png_set_PLTE(png, info, palette, 16);

        png_write_info(png, info);

        BYTE *rows[256];
        for (int i = savemsb ; i < 256 ; i++)
            rows[i-savemsb] = &seen[i*256];

        png_write_image(png, rows);
        png_write_end(png, NULL);

        fclose(f);
    }
    else
        perror("fopen");
}

void write_map (const char *filename)
{
    char buf[256];
    strncpy(buf, filename, sizeof(buf)-4);

    // Change any file extension for .map
    char *p = strrchr(buf, '.');
    if (p) *p = '\0';
    strcat(buf, ".map");

    FILE *f = fopen(buf, "wb");
    if (f)
    {
        BYTE map[0x10000/8] = {};
        int mapstart = 256*savemsb/8;

        // Mask to determine which entries to include in the map
        BYTE map_mask = instrmap ? MARK_INSTR : 0xff;

        // Build the compact map (bits filled in the order 0 to 7)
        for (int i = 0 ; i < sizeof(seen) ; i++)
            map[i/8] |= ((seen[i] & map_mask) != 0) << (i&7);

        if (!fwrite(map+mapstart, sizeof(map)-mapstart, 1, f))
            perror("fwrite");

        fclose(f);
    }
    else
        perror("fopen");
}


int main (int argc, char *argv[])
{
    const char *file = NULL;

    for (int i = 1 ; i < argc ; i++)
    {
        // Option?
        if (argv[i][0] == '-')
        {
            for (char *p = argv[i]+1 ; *p ; p++)
            {
                switch (*p)
                {
                    case 'b': basictrace = false; break; // skip BASIC scan for USRs
                    case 'd': decaddr = true; break;     // output addresses in decimal
                    case 'i': im2trace = false; break;   // skip IM 2 trace
                    case 'm': mapsave = true; break;     // save code bitmap
                    case 'r': savemsb = 0x00; break;     // include ROM in output image
                    case 's': pngsave = false; break;    // skip saving PNG image
                    case 'v': verbose++; break;          // increase verbosity level
                    case 'z': instrmap = true; break;    // only Z80 instruction start in map

                    default:
                        fprintf(stderr, "Unknown option: -%c\n", *p);
                        exit(1);
                        break;
                }
            }
        }
        else if (!file)
            file = argv[i];
        else
        {
            fprintf(stderr, "Unexpected argument: %s\n", argv[i]);
            exit(1);
        }
    }

    if (!file)
    {
        fprintf(stderr, "Usage: %s [-bdimrsvz] <snapshot>\n", argv[0]);
        return 1;
    }
    else if (!read_rom("48.rom") && !read_rom(ROM_DIR "48.rom"))
    {
        perror(ROM_DIR "48.rom");
        return 1;
    }
    else if (!read_snapshot(file))
        return 1;

    // Trace from PC in snapshot
    mark = 4; // green
    trace_addr(reg_pc, reg_sp, reg_sp, 0); // top-level, ret allowed

    // Trace using USR statements in BASIC and the current editing line
    if (basictrace)
    {
        trace_prog();
        trace_eline();
    }

    // Trace IM 2 handler if active, or setup detected in code
    if (im2trace && reg_im == 2)
        trace_im2(reg_i);
    else if (im2trace && poss_im == 2)
        trace_im2(poss_i);

    if (pngsave)
        write_png(file);

    if (mapsave)
        write_map(file);

    int n = 0;
    for (size_t i = 0x4000 ; i < sizeof(seen) ; i++)
        n += seen[i] != 0;

    if (basictrace)
        printf("Traced %d Z80 bytes, BASIC length %d.\n", n-basiclen, basiclen);
    else
        printf("Traced %d Z80 bytes.\n", n);

    return 0;
}
