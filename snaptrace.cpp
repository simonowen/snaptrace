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

#define PROG   0x5c53   // contains address of BASIC program
#define VARS   0x5c4b   // contains address of BASIC variables
#define E_LINE 0x5c59   // contains address being typed in
#define STKEND 0x5c65   // contains start address of spare space

typedef unsigned char BYTE;
typedef unsigned short WORD;

WORD reg_pc, reg_sp;    // PC and SP from snapshot
BYTE reg_i, reg_im;     // I and interrupt mode from snapshot

BYTE poss_i, poss_im;   // possible I and IM values in the code

BYTE mem[0x10000];      // 64K address space, first 16K ROM
BYTE seen[0x10000];     // code locations visited
BYTE nocall[0x10000];   // blacklisted calls due to stack manipulation
BYTE mark;              // current marker colour bit to combine into seen[pc]
int basiclen;           // count of bytes in BASIC listing

int savemsb = 0x40;     // 0x40 to save 48K RAM, 0x00 to save full 64K
int verbose = 0;        // 0-2 for tracing detail levels
bool usrtrace = true;   // trace USR statements found in BASIC (enabled, -u to disable)
bool im2trace = true;   // trace IM 2 interrupt handler (enabled, -2 to disable)
bool pngsave = true;    // save output as PNG image (enabled, -s to disable)


bool trace_addr (WORD pc, WORD sp, WORD basesp, bool toplevel)
{
    WORD addr;
    BYTE op;
    bool ddfd = false;

    // Continuing beyond ROM loader is unsafe as it may rely on loaded code
    if (pc == 0x0556)
    {
        printf("%04X: stopping at ROM loader\n", pc);
        return false;
    }

    // Loop until we reach a previously visited location
    while (!(seen[pc] & mark))
    {
        if (verbose > 1 && !ddfd) printf("PC=%04X SP=%04X %s\n", pc, sp, toplevel?"top-level":"");

        // Next opcode, mark as visited
        op = mem[pc];
        seen[pc++] |= mark;

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
                        if (toplevel)
                        {
                            addr = (mem[sp+1] << 8) | mem[sp];
                            if (verbose) printf("%04X: reti/retn (top-level)\n", pc-2);
                            trace_addr(addr, sp+2, sp+2, toplevel);
                        }
                        return true;

                    case 0x7b: // ld sp,(nn)
                        basesp = sp;
                    case 0x43: case 0x53: case 0x63: case 0x73: // ld (nn),rr
                    case 0x4b: case 0x5b: case 0x6b: // ld rr,(nn)
                        seen[pc++] |= mark;
                        seen[pc++] |= mark;
                        break;

                    case 0x47: // ld i,a
                        if (poss_i < 0x40 && mem[pc-4] == 0x3e/*ld a,n*/)
                        {
                            poss_i = mem[pc-3];
                            if (verbose > 1) printf(" LD A,%02X ; LD I,A\n", pc-4, poss_i);
                        }
                        break;

                    case 0x5e: // im 2
                        if (verbose > 1) printf(" IM 2\n");
                        poss_im = 2;
                        break;
                }
                break;


            case 0x00: // nop
                if (pc-1 >= 0x4000 && pc < (0xffff-MAX_NOP_RUN) && !memcmp(mem+pc, mem+pc+1, MAX_NOP_RUN-1))
                {
                    printf("%04X: *** suspicious block of %d+ NOPs ***\n", pc-1, MAX_NOP_RUN);
                    return true;
                }
                break;

            case 0xe3: // ex (sp),hl
                if (verbose > 1) printf(" ex (sp),hl\n");

                if (sp == basesp) // pointing to return adddress?
                {
                    if (pc >= 0x4000) printf("%04X: stopping at ex (sp) on return address\n", pc-1);
                    return false;
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

                addr = pc+static_cast<signed char>(mem[pc-1]);
                if (verbose) printf("%04X: %s %04X\n", pc-2, (op==0x10)?"djnz":"jr", addr);

                bool ret1 = trace_addr(addr, sp, basesp, toplevel);
                bool ret2 = (op == 0x18/*jr*/) || trace_addr(pc, sp, basesp, toplevel);
                return ret1 && ret2;
            }

            case 0xc3: // jp
            case 0xc2: case 0xca: case 0xd2: case 0xda: case 0xe2: case 0xea: case 0xf2: case 0xfa: // jp cc
            {
                seen[pc++] |= mark;
                seen[pc++] |= mark;

                addr = (mem[pc-1] << 8) | mem[pc-2];
                if (verbose) printf("%04X: jp %04X\n", pc-3, addr);

                bool ret1 = trace_addr(addr, sp, basesp, toplevel);
                bool ret2 = (op == 0xc3/*jp*/) || trace_addr(pc, sp, basesp, toplevel);
                return ret1 && ret2;
            }

            case 0xcd: // call
            case 0xc4: case 0xcc: case 0xd4: case 0xdc: case 0xe4: case 0xec: case 0xf4: case 0xfc: // call cc
            case 0xc7: case 0xcf: case 0xd7: case 0xdf: case 0xe7: case 0xef: case 0xf7: case 0xff: // rst

                if ((op & 0xc7) == 0xc7) // rst?
                {
                    addr = op & 0x38;
                    if (verbose) printf("%04X: rst %02X %s\n", pc-1, addr, nocall[addr]?"(blacklisted)":"");
                }
                else // call
                {
                    seen[pc++] |= mark;
                    seen[pc++] |= mark;

                    addr = (mem[pc-1] << 8) | mem[pc-2];
                    if (verbose) printf("%04X: call %04X %s\n", pc-3, addr, nocall[addr]?"(blacklisted)":"");
                }

                if (nocall[addr])
                    return true;

                // Recursive call to trace CALL
                if (!trace_addr(addr, sp-2, sp-2, false))
                {
                    if (pc >= 0x4000) printf("%04X: blacklisted call to %04X\n", pc, addr);
                    nocall[addr] = 1;
                    return true;
                }
                break;

            case 0xc9: // ret
            case 0xc0: case 0xc8: case 0xd0: case 0xd8: case 0xe0: case 0xe8: case 0xf0: case 0xf8: // ret cc
                if (sp < basesp)
                {
                    if (pc >= 0x4000) printf("%04X: ret to stacked data\n", pc-1);
                    return true;
                }

                if (toplevel)
                {
                    addr = (mem[sp+1] << 8) | mem[sp];
                    if (verbose) printf("%04X: ret (top-level)\n", pc-1);
                    trace_addr(addr, sp+2, sp+2, toplevel);
                }

                if (op == 0xc9) // ret
                {
                    if (verbose) printf("%04X: ret\n", pc-1);
                    return true;
                }
                break;

            case 0xe9: // jp (hl)
                return true;


            case 0xc5: case 0xd5: case 0xe5: case 0xf5: // push rr
                if (verbose > 1) printf(" push\n");
                sp -= 2;
                break;

            case 0xc1: case 0xd1: case 0xe1: case 0xf1: // pop rr
                if (verbose > 1) printf(" pop\n");

                if (!toplevel && sp == basesp)
                {
                    // Return pop followed by data access?
                    if (!ddfd &&
                        ((op == 0xe1 && (mem[pc] & 0xc7) == 0x46) || // pop hl ; ld r,(hl)
                         (op == 0xd1 &&  mem[pc]         == 0x1a) || // pop de ; ld a,(de)
                         (op == 0xc1 &&  mem[pc]         == 0x0a)))  // pop bc ; ld a,(bc)
                    {
                        if (pc >= 0x4000) printf("%04X: stopping at return address data access\n", pc);
                        return false;
                    }
                    else if (ddfd && op == 0xe1) // pop ix/iy
                    {
                        for (WORD w = 0 ; w < 10 ; w++) // access must be within ~10 bytes
                        {
                            if (mem[pc+w] == mem[pc-2] && (mem[pc+w+1] & 0xc7) == 0x46 && mem[pc+w+2] <= 0x01) // ld r,(ix/iy+0/1)
                            {
                                if (pc >= 0x4000) printf("%04X: stopping at return address data access\n", pc+w);
                                return false;
                            }
                        }
                    }

                    if (pc >= 0x4000) printf("%04X: return address popped\n", pc-1-ddfd);
                    return true;
                }

                sp += 2;
                break;

            case 0x33:  // inc sp
                if (verbose > 1) printf(" inc sp\n");
                sp++;
                break;

            case 0x3b:  // dec sp
                if (verbose > 1) printf(" dec sp\n");
                sp--;
                break;


            case 0x06: case 0x0e: case 0x16: case 0x1e: case 0x26: case 0x2e: case 0x3e: // ld r,n
            case 0xc6: case 0xce: case 0xd6: case 0xde: case 0xe6: case 0xee: case 0xf6: case 0xfe: // add/adc/sub/sbc/and/xor/or/cp n
            case 0xd3: case 0xdb: // out (n),a ; in a,(n)
                seen[pc++] |= mark;
                break;

            case 0x31:  // ld sp,nn
                basesp = sp;
            case 0x01: case 0x11: case 0x21: // ld rr,nn
            case 0x22: case 0x2a: case 0x32: case 0x3a: // ld (nn),hl ; ld hl,(nn) ; ld (nn),a ; ld a,(nn)
                seen[pc++] |= mark;
                seen[pc++] |= mark;
                break;

            case 0x40: case 0x49: case 0x52: case 0x5b: case 0x64: case 0x6d: case 0x7f: // ld r,r
                printf("%04X: *** suspicious ld r,r ***\n", pc-1);
                return true;
        }

        ddfd = false;
    }

    return true;
}

// Trace a given address, if it looks safe to do
void trace_safe (WORD pc, WORD sp)
{
    if (mem[pc] == 0x00 || mem[pc] == 0xff)
        printf(" skipped due to suspicious code start (%02X)\n", mem[pc]);
    else
        trace_addr(pc, sp, sp, false);
}


void trace_line (WORD addr, int len, int line)
{
    int i;
    bool inquotes = false;

    if (verbose)
        printf("%04X: BASIC line %u len %u\n", addr, line, len);

    for (i = addr ; i < addr+len ; i++)
    {
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
                    printf("Found USR VAL$ %u (%04X) on edit line\n", addr, addr);
                else
                    printf("Found USR VAL$ %u (%04X) on line %u\n", addr, addr, line);

                mark = 2; // red
                trace_safe(addr, reg_sp);
            }
        }
        else if (isdigit(mem[i+1]))
        {
            // Skip the string of digits, which can't be trusted
            for (i++ ; isdigit(mem[i]) ; i++);

            // 5-byte number format with an integer?
            if (mem[i] == 0x0e && mem[i+1] == 0 && mem[i+2] == 0 && mem[i+5] == 0)
            {
                WORD addr = (mem[i+4] << 8) | mem[i+3];
                if (line < 0)
                    printf("Found USR %u (%04X) on edit line\n", addr, addr);
                else
                    printf("Found USR %u (%04X) on line %u\n", addr, addr, line);

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
        printf("Tracing IM 2 from %04X\n", im_addr);

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
                    printf("%s: PC=%04X SP=%04X I=%02X IM=%u\n", filename, reg_pc, reg_sp, reg_i, reg_im);

                    mark = 4; // green
                    trace_addr(reg_pc, reg_sp, reg_sp, true);

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

        png_color palette[256] = { {0,0,0}, {64,64,255}, {255,64,64}, {255,64,255}, {64,255,64}, {64,255,255}, {255,255,64}, {255,255,255} };
        png_set_PLTE(png, info, palette, 8);

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


int main (int argc, char *argv[])
{
    const char *file = NULL;

    for (int i = 1 ; i < argc ; i++)
    {
        if (!strcmp(argv[i], "-v")) // verbose
            verbose++;
        else if (!strcmp(argv[i], "-vv")) // more verbose
            verbose += 2;
        else if (!strcmp(argv[i], "-u")) // skip USR trace
            usrtrace = false;
        else if (!strcmp(argv[i], "-2")) // skip IM 2 trace
            im2trace = false;
        else if (!strcmp(argv[i], "-r")) // include ROM in output image
            savemsb = 0x00;
        else if (!strcmp(argv[i], "-s")) // skip saving PNG image
            pngsave = false;
        else if (argv[i][0] == '-')
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
        else if (!file)
            file = argv[i];
        else
            fprintf(stderr, "Unexpected argument: %s\n", argv[i]);
    }

    if (!file)
    {
        fprintf(stderr, "Usage: %s [-v] [-u] [-2] [-r] [-s] <snapshot>\n", argv[0]);
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
    trace_addr(reg_pc, reg_sp, reg_sp, true);

    // Trace using USR statements in BASIC and the current editing line
    if (usrtrace)
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

    int n = 0;
    for (size_t i = 0x4000 ; i < sizeof(seen) ; i++)
        n += seen[i] != 0;

    printf("Traced %d Z80 bytes, BASIC length %d.\n", n-basiclen, basiclen);
    return 0;
}
