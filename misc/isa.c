#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include "isa.h"

#include<sys/ipc.h>
#include<sys/shm.h>
#include<fcntl.h>
#include<sys/file.h>

/* Are we running in GUI mode? */
extern int gui_mode;

/* Bytes Per Line = Block size of memory */
#define BPL 32

// #define NAIVE
// #define DEBUG

struct {
    char *name;
    int id;
} reg_table[REG_ERR+1] = 
{
    {"%eax",   REG_EAX},
    {"%ecx",   REG_ECX},
    {"%edx",   REG_EDX},
    {"%ebx",   REG_EBX},
    {"%esp",   REG_ESP},
    {"%ebp",   REG_EBP},
    {"%esi",   REG_ESI},
    {"%edi",   REG_EDI},
    {"----",  REG_ERR},
    {"----",  REG_ERR},
    {"----",  REG_ERR},
    {"----",  REG_ERR},
    {"----",  REG_ERR},
    {"----",  REG_ERR},
    {"----",  REG_ERR},
    {"----",  REG_NONE},
    {"----",  REG_ERR}
};


// lock counter
int lock_counter = 0;

// cache related begin (make calls to memory related)
// caller should make sure that read/write operate on a valid entry
// lock should be handled by caller
// hash the lower 10 bits
int cached(mem_t m, word_t pos)
{
    return m->label[pos & MASK] == pos;
}

void read_cache(mem_t m, word_t pos, byte_t *dest)
{
    *dest = m->cache[pos & MASK];
}

void write_cache(mem_t m, word_t pos, byte_t val)
{
    m->cache[pos & MASK] = val;
}

// simply write back if collide
void cache(mem_t m, word_t pos)
{
    int k = pos & MASK;
    if(k == 0 && m->label[k] != -1 || k != 0 && m->label[k] != 0)
        if(m->label[k] < m->len)
            m->contents[m->label[k]] = m->cache[k];
        else
            m->shared[m->label[k] - m->len] = m->cache[k];
    m->label[k] = pos;
    if(pos < m->len)
        m->cache[k] = m->contents[pos];
    else
        m->cache[k] = m->shared[pos - m->len];
}
// cache related end

// transfering related begin (make calls to cache related)
// check should be done before any commit
// lock should be handled by caller
/*
    transfering conventions:
        system preserved memory begins at (1 << 13) + (1 << 12) + (1 << 11)
        addr (1 << 13) + (1 << 12) + (1 << 11)
        [SP, SP + 4) stores number of entries involved in the commit
        [SP + 4, SP + 8) stores the token of current update
        an entry consists of 5 bytes, (pos, val)
*/
void check_update(mem_t m)
{
    int n =
        (m->shared[SP] << 0) +
        (m->shared[SP + 1] << 8) +
        (m->shared[SP + 2] << 16) +
        (m->shared[SP + 3] << 24);
    int i, pos, val;
    if(!m->fd)
        return;
    for(i = 0; i < n; i++)
    {
        pos =
            (m->shared[SP + 8 + i * 5] << 0) +
            (m->shared[SP + 8 + i * 5 + 1] << 8) +
            (m->shared[SP + 8 + i * 5 + 2] << 16) +
            (m->shared[SP + 8 + i * 5 + 3] << 24);
        val = (m->shared[SP + 8 + i * 5 + 4]);
        if(cached(m, pos))
            write_cache(m, pos, val);
    }
    int t =
        (m->shared[SP + 4] << 0) +
        (m->shared[SP + 5] << 8) +
        (m->shared[SP + 6] << 16) +
        (m->shared[SP + 7] << 24);
    // printf("checking update, n: %d, token: %d, my_token: %d\n", n, t, m->token);
    if(t == m->token)
        return;
    else
    {
        t = (rand() << 16) + (rand());
        m->token = t;
        m->shared[SP + 4] = (t << 0) & 0xFF;
        m->shared[SP + 5] = (t << 8) & 0xFF;
        m->shared[SP + 6] = (t << 16) & 0xFF;
        m->shared[SP + 7] = (t << 24) & 0xFF;
        memset(m->shared + SP, 0, 4);
    }
}

void commit_update(mem_t m, word_t pos, byte_t val)
{
    int n =
        (m->shared[SP] << 0) +
        (m->shared[SP + 1] << 8) +
        (m->shared[SP + 2] << 16) +
        (m->shared[SP + 3] << 24);
    if(n >= MAXN)
        return;
    if(!m->fd)
        return;
    m->shared[SP + 8 + n * 5] = (pos >> 0) & 0xFF;
    m->shared[SP + 8 + n * 5 + 1] = (pos >> 8) & 0xFF;
    m->shared[SP + 8 + n * 5 + 2] = (pos >> 16) & 0xFF;
    m->shared[SP + 8 + n * 5 + 3] = (pos >> 24) & 0xFF;
    m->shared[SP + 8 + n * 5 + 4] = val;
    n++;
    m->shared[SP] = (n >> 0) & 0xFF;
    m->shared[SP + 1] = (n >> 8) & 0xFF;
    m->shared[SP + 2] = (n >> 16) & 0xFF;
    m->shared[SP + 3] = (n >> 24) & 0xFF;
}
// transfering related end

reg_id_t find_register(char *name)
{
    int i;
    for (i = 0; i < REG_NONE; i++)
        if (!strcmp(name, reg_table[i].name))
            return reg_table[i].id;
    return REG_ERR;
}

char *reg_name(reg_id_t id)
{
    if (id >= 0 && id < REG_NONE)
        return reg_table[id].name;
    else
        return reg_table[REG_NONE].name;
}

/* Is the given register ID a valid program register? */
int reg_valid(reg_id_t id)
{
    return id >= 0 && id < REG_NONE && reg_table[id].id == id;
}

instr_t instruction_set[] = 
{
    {"nop",    HPACK(I_NOP, F_NONE), 1, NO_ARG, 0, 0, NO_ARG, 0, 0 },
    {"halt",   HPACK(I_HALT, F_NONE), 1, NO_ARG, 0, 0, NO_ARG, 0, 0 },
    {"rrmovl", HPACK(I_RRMOVL, F_NONE), 2, R_ARG, 1, 1, R_ARG, 1, 0 },
    /* Conditional move instructions are variants of RRMOVL */
    {"cmovle", HPACK(I_RRMOVL, C_LE), 2, R_ARG, 1, 1, R_ARG, 1, 0 },
    {"cmovl", HPACK(I_RRMOVL, C_L), 2, R_ARG, 1, 1, R_ARG, 1, 0 },
    {"cmove", HPACK(I_RRMOVL, C_E), 2, R_ARG, 1, 1, R_ARG, 1, 0 },
    {"cmovne", HPACK(I_RRMOVL, C_NE), 2, R_ARG, 1, 1, R_ARG, 1, 0 },
    {"cmovge", HPACK(I_RRMOVL, C_GE), 2, R_ARG, 1, 1, R_ARG, 1, 0 },
    {"cmovg", HPACK(I_RRMOVL, C_G), 2, R_ARG, 1, 1, R_ARG, 1, 0 },
    /* arg1hi indicates number of bytes */
    {"irmovl", HPACK(I_IRMOVL, F_NONE), 6, I_ARG, 2, 4, R_ARG, 1, 0 },
    {"rmmovl", HPACK(I_RMMOVL, F_NONE), 6, R_ARG, 1, 1, M_ARG, 1, 0 },
    {"mrmovl", HPACK(I_MRMOVL, F_NONE), 6, M_ARG, 1, 0, R_ARG, 1, 1 },
    {"addl",   HPACK(I_ALU, A_ADD), 2, R_ARG, 1, 1, R_ARG, 1, 0 },
    {"subl",   HPACK(I_ALU, A_SUB), 2, R_ARG, 1, 1, R_ARG, 1, 0 },
    {"andl",   HPACK(I_ALU, A_AND), 2, R_ARG, 1, 1, R_ARG, 1, 0 },
    {"xorl",   HPACK(I_ALU, A_XOR), 2, R_ARG, 1, 1, R_ARG, 1, 0 },
    /* arg1hi indicates number of bytes */
    {"jmp",    HPACK(I_JMP, C_YES), 5, I_ARG, 1, 4, NO_ARG, 0, 0 },
    {"jle",    HPACK(I_JMP, C_LE), 5, I_ARG, 1, 4, NO_ARG, 0, 0 },
    {"jl",     HPACK(I_JMP, C_L), 5, I_ARG, 1, 4, NO_ARG, 0, 0 },
    {"je",     HPACK(I_JMP, C_E), 5, I_ARG, 1, 4, NO_ARG, 0, 0 },
    {"jne",    HPACK(I_JMP, C_NE), 5, I_ARG, 1, 4, NO_ARG, 0, 0 },
    {"jge",    HPACK(I_JMP, C_GE), 5, I_ARG, 1, 4, NO_ARG, 0, 0 },
    {"jg",     HPACK(I_JMP, C_G), 5, I_ARG, 1, 4, NO_ARG, 0, 0 },
    {"call",   HPACK(I_CALL, F_NONE),    5, I_ARG, 1, 4, NO_ARG, 0, 0 },
    {"ret",    HPACK(I_RET, F_NONE), 1, NO_ARG, 0, 0, NO_ARG, 0, 0 },
    {"pushl",  HPACK(I_PUSHL, F_NONE) , 2, R_ARG, 1, 1, NO_ARG, 0, 0 },
    {"popl",   HPACK(I_POPL, F_NONE) ,  2, R_ARG, 1, 1, NO_ARG, 0, 0 },
    {"iaddl",  HPACK(I_IADDL, F_NONE), 6, I_ARG, 2, 4, R_ARG, 1, 0 },
    {"leave",  HPACK(I_LEAVE, F_NONE), 1, NO_ARG, 0, 0, NO_ARG, 0, 0 },
    /* this is just a hack to make the I_POP2 code have an associated name */
    {"pop2",   HPACK(I_POP2, F_NONE) , 0, NO_ARG, 0, 0, NO_ARG, 0, 0 },
    // swap added
    {"swap", HPACK(I_SWAP, F_NONE), 6, R_ARG, 1, 1, M_ARG, 1, 0},

    /* For allocation instructions, arg1hi indicates number of bytes */
    {".byte",  0x00, 1, I_ARG, 0, 1, NO_ARG, 0, 0 },
    {".word",  0x00, 2, I_ARG, 0, 2, NO_ARG, 0, 0 },
    {".long",  0x00, 4, I_ARG, 0, 4, NO_ARG, 0, 0 },
    {NULL,     0   , 0, NO_ARG, 0, 0, NO_ARG, 0, 0 }
};

instr_t invalid_instr =
{"XXX",     0   , 0, NO_ARG, 0, 0, NO_ARG, 0, 0 };

instr_ptr find_instr(char *name)
{
    int i;
    for (i = 0; instruction_set[i].name; i++)
        if (strcmp(instruction_set[i].name,name) == 0)
            return &instruction_set[i];
    return NULL;
}

/* Return name of instruction given its encoding */
char *iname(int instr) {
    int i;
    for (i = 0; instruction_set[i].name; i++) {
        if (instr == instruction_set[i].code)
            return instruction_set[i].name;
    }
    return "<bad>";
}


instr_ptr bad_instr()
{
    return &invalid_instr;
}


mem_t init_naive_mem(int len)
{

    mem_t result = (mem_t) malloc(sizeof(mem_rec));
    len = ((len+BPL-1)/BPL)*BPL;
    result->len = len;
    result->contents = (byte_t *) calloc(len, 1);

    result->shared = 0;
    result->fd = 0;

    return result;
}

mem_t init_mem(int len)
{

    int t;
    #ifdef NAIVE
    return init_naive_mem(len);
    #endif
    mem_t result = (mem_t) malloc(sizeof(mem_rec));
    len = ((len+BPL-1)/BPL)*BPL;

    result->fd = open("42", O_RDONLY | O_CREAT, S_IRUSR);

    lock(result);

    result->len = len;
    result->contents = (byte_t *) calloc(len, 1);

    result->cachesize = CACHE_SIZE;
    result->cache = (byte_t *) calloc(result->cachesize, 1);
    result->label = (int *) calloc(result->cachesize * sizeof(int), 1);

    t = ftok("42", "a");
    t = shmget(t, len, IPC_CREAT | 0777);
    result->shared = (byte_t *) shmat(t, 0, 42); // the third parameter does not matter
    if(result->shared != -1)
        memset(result->shared, 0, result->len);
    else
    {
        printf("shared mem creating failure.\n");
        result->shared = 0;
    }

    result->label[0] = -1; // important!!!

    unlock(result);

    return result;
}

// lock related begin
void lock(mem_t m)
{
    if(!m->fd)
        return;
    if(!lock_counter)
        flock(m->fd, LOCK_EX);
    lock_counter++;

    #ifdef DEBUG
    printf("acquiring %d locks.\n", lock_counter);
    #endif
}

void unlock(mem_t m)
{
    if(!m->fd)
        return;
    lock_counter--;
    #ifdef DEBUG
    printf("releasing %d locks.\n", lock_counter);
    #endif
    if(!lock_counter)
        flock(m->fd, LOCK_UN);
}
// lock related end

void clear_mem(mem_t m)
{
    memset(m->contents, 0, m->len);
    if(m->shared)
    {
        lock(m);
        memset(m->shared, 0, m->len);
        memset(m->cache, 0, m->cachesize);
        memset(m->label, 0, m->cachesize * sizeof(int));
        unlock(m);
    }
}

void free_mem(mem_t m)
{
    free((void *) m->contents);
    if(m->shared)
    {
        lock(m);
        if(!m->fd)
            free((void *) m->shared);
        free((void *) m->cache);
        free((void *) m->label);
        unlock(m);
    }
    free((void *) m);
}

mem_t copy_mem(mem_t oldm)
{
    mem_t newm;
    if(oldm->shared)
    {
        int i;
        byte_t t;
        lock(oldm);
        newm = init_naive_mem(oldm->len);
        newm->shared = (byte_t *) calloc(oldm->len, 1);
        newm->cachesize = oldm->cachesize;
        newm->cache = (byte_t *) calloc(oldm->cachesize, 1);
        newm->label = (int *) calloc(oldm->cachesize * sizeof(int), 1);

        memcpy(newm->contents, oldm->contents, oldm->len);
        memcpy(newm->shared, oldm->shared, oldm->len);
        memcpy(newm->cache, oldm->cache, oldm->cachesize);
        memcpy(newm->label, oldm->label, oldm->cachesize * sizeof(int));
        newm->token = oldm->token;
        unlock(oldm);
    }
    else
    {
        newm = init_naive_mem(oldm->len);
        memcpy(newm->contents, oldm->contents, oldm->len);
    }
    return newm;
}

bool_t diff_mem(mem_t oldm, mem_t newm, FILE *outfile)
{
    word_t pos;
    int len = oldm->len;
    bool_t diff = FALSE;
    if (newm->len < len)
        len = newm->len;
    for (pos = 0; (!diff || outfile) && pos < len; pos += 4) {
        word_t ov = 0;  word_t nv = 0;
        #ifdef DEBUG
        printf("differing 0x%.4x\n", pos);
        #endif
        get_word_val(oldm, pos, &ov);
        get_word_val(newm, pos, &nv);
        if (nv != ov) {
            diff = TRUE;
            if (outfile)
                fprintf(outfile, "0x%.4x:\t0x%.8x\t0x%.8x\n", pos, ov, nv);
        }
    }
    if(oldm->shared && newm->shared)
    {
        lock(oldm);
        lock(newm);
        check_update(oldm);
        check_update(newm);
        for (pos = len; (!diff || outfile) && pos < len * 2; pos += 4) {
            word_t ov = 0;  word_t nv = 0;
            get_word_val(oldm, pos, &ov);
            get_word_val(newm, pos, &nv);
            if (nv != ov) {
                diff = TRUE;
                if (outfile)
                    fprintf(outfile, "0x%.4x:\t0x%.8x\t0x%.8x\n", pos, ov, nv);
            }
        }
        unlock(newm);
        unlock(oldm);
    }
    return diff;
}

int hex2dig(char c)
{
    if (isdigit((int)c))
        return c - '0';
    if (isupper((int)c))
        return c - 'A' + 10;
    else
        return c - 'a' + 10;
}

#define LINELEN 4096
int load_mem(mem_t m, FILE *infile, int report_error)
{
    /* Read contents of .yo file */
    char buf[LINELEN];
    char c, ch, cl;
    int byte_cnt = 0;
    int lineno = 0;
    word_t bytepos = 0;
    int empty_line = 1;
    int addr = 0;
    char hexcode[15];

#ifdef HAS_GUI
    /* For display */
    int line_no = 0;
    char line[LINELEN];
#endif /* HAS_GUI */   

    int index = 0;

    while (fgets(buf, LINELEN, infile)) {
        int cpos = 0;
        empty_line = 1;
        lineno++;
        /* Skip white space */
        while (isspace((int)buf[cpos]))
            cpos++;

        if (buf[cpos] != '0' ||
                (buf[cpos+1] != 'x' && buf[cpos+1] != 'X'))
            continue; /* Skip this line */      
        cpos+=2;

        /* Get address */
        bytepos = 0;
        while (isxdigit((int)(c=buf[cpos]))) {
            cpos++;
            bytepos = bytepos*16 + hex2dig(c);
        }

        while (isspace((int)buf[cpos]))
            cpos++;

        if (buf[cpos++] != ':') {
            if (report_error) {
                fprintf(stderr, "Error reading file. Expected colon\n");
                fprintf(stderr, "Line %d:%s\n", lineno, buf);
                fprintf(stderr,
                        "Reading '%c' at position %d\n", buf[cpos], cpos);
            }
            return 0;
        }

        addr = bytepos;

        while (isspace((int)buf[cpos]))
            cpos++;

        index = 0;

        /* Get code */
        while (isxdigit((int)(ch=buf[cpos++])) && 
                isxdigit((int)(cl=buf[cpos++]))) {
            byte_t byte = 0;
            if (!m->shared && bytepos >= m->len || bytepos >= m->len * 2) {
                if (report_error) {
                    fprintf(stderr,
                            "Error reading file. Invalid address. 0x%x\n",
                            bytepos);
                    fprintf(stderr, "Line %d:%s\n", lineno, buf);
                }
                return 0;
            }
            byte = hex2dig(ch)*16+hex2dig(cl);
            // m->contents[bytepos++] = byte;
            // printf("about to write 0x%.4x.\n", bytepos);
            set_byte_val(m, bytepos++, byte);
            // printf("0x%.4x written.\n", bytepos);
            byte_cnt++;
            empty_line = 0;
            hexcode[index++] = ch;
            hexcode[index++] = cl;
        }
        /* Fill rest of hexcode with blanks */
        for (; index < 12; index++)
            hexcode[index] = ' ';
        hexcode[index] = '\0';

#ifdef HAS_GUI
        if (gui_mode) {
            /* Now get the rest of the line */
            while (isspace((int)buf[cpos]))
                cpos++;
            cpos++; /* Skip over '|' */

            index = 0;
            while ((c = buf[cpos++]) != '\0' && c != '\n') {
                line[index++] = c;
            }
            line[index] = '\0';
            if (!empty_line)
                report_line(line_no++, addr, hexcode, line);
        }
#endif /* HAS_GUI */ 
    }
    return byte_cnt;
}

bool_t get_byte_val(mem_t m, word_t pos, byte_t *dest)
{
    // int addr = -1, value;
    if (pos < 0 || (!m->shared && pos >= m->len) || pos >= m->len * 2)
        return FALSE;

    if(m->shared)
    {
        lock(m);
        #ifdef DEBUG
        printf("reading 0x%.4x\n", pos);
        #endif
        check_update(m);
        #ifdef DEBUG
        printf("update checked.\n");
        #endif
        if(!cached(m, pos))
            cache(m, pos);
        #ifdef DEBUG
        printf("cache updated.\n");
        #endif
        read_cache(m, pos, dest);
        #ifdef DEBUG
        printf("cache read.\n");
        #endif
        /*
        else if(pos < m->len)
            *dest = m->contents[pos];
        else
            *dest = m->shared[pos - m->len];
        */
        unlock(m);
    }
    else
        *dest = m->contents[pos];
    return TRUE;
}

bool_t get_word_val(mem_t m, word_t pos, word_t *dest)
{
    int i;
    word_t val;
    byte_t t;
    if (pos < 0 || (!m->shared && pos + 4 > m->len) || pos + 4 > m->len * 2)
        return FALSE;
    if(m->shared)
    {
        lock(m);
        val = 0;
        for(i = 0; i < 4; i++)
        {
            get_byte_val(m, pos + i, &t);
            val |= t << (8 * i);
        }
        *dest = val;
        unlock(m);
    }
    else
    {
        val = 0;
        for (i = 0; i < 4; i++)
            val = val | m->contents[pos+i]<<(8*i);
        *dest = val;
    }
    return TRUE;
}

bool_t swap_word_val(mem_t m, word_t pos, word_t *dest)
{
    int i;
    word_t val;
    byte_t t;
    if (pos < 0 || (!m->shared && pos + 4 > m->len) || pos + 4 > m->len * 2)
        return FALSE;
    if(m->shared)
    {
        lock(m);
        val = 0;
        for(i = 0; i < 4; i++)
        {
            get_byte_val(m, pos + i, &t);
            val |= t << (8 * i);
        }
        set_word_val(m, pos, *dest);
        *dest = val;
        unlock(m);
    }
    else
    {
        val = 0;
        for (i = 0; i < 4; i++)
            val = val | m->contents[pos+i]<<(8*i);
        set_word_val(m, pos, *dest);
        *dest = val;
    }
    return TRUE;
}

bool_t set_byte_val(mem_t m, word_t pos, byte_t val)
{
    if (pos < 0 || !m->shared && pos >= m->len || pos >= m->len * 2)
        return FALSE;
    if(m->shared)
    {
        lock(m);
        #ifdef DEBUG
        printf("setting 0x%.4x to be 0x%.2x\n", pos, val);
        #endif
        check_update(m);
        if(!cached(m, pos))
            cache(m, pos);
        write_cache(m, pos, val);
        if(pos >= m->len)
            commit_update(m, pos, val);
        unlock(m);
    }
    else
    {
        m->contents[pos] = val;
    }
    return TRUE;
}

bool_t set_word_val(mem_t m, word_t pos, word_t val)
{
    int i;
    if (pos < 0 || pos + 4 > m->len && !m->shared || pos + 4 > m->len * 2)
        return FALSE;
    if(m->shared)
    {
        lock(m);
        for(i = 0; i < 4; i++)
        {
            set_byte_val(m, pos + i, val & 0xFF);
            val >>= 8;
        }
        unlock(m);
    }
    else
    {
        for (i = 0; i < 4; i++) {
            m->contents[pos+i] = val & 0xFF;
            val >>= 8;
        }
    }
    return TRUE;
}

void dump_memory(FILE *outfile, mem_t m, word_t pos, int len)
{
    int i, j;
    while (pos % BPL) {
        pos --;
        len ++;
    }

    len = ((len+BPL-1)/BPL)*BPL;

    if(m->shared)
    {
        lock(m);
        check_update(m);
        if(pos + len > m->len * 2)
            len = m->len * 2 - pos;
        for(i = 0; i < len; i += BPL)
        {
            word_t val = 0;
            fprintf(outfile, "0x%.4x:", pos+i);
            for (j = 0; j < BPL; j += 4)
            {
                get_word_val(m, pos + i + j, &val);
                fprintf(outfile, " %.8x", val);
            }
        }
        unlock(m);
    }
    else
    {
        if (pos+len > m->len)
            len = m->len-pos;

        for (i = 0; i < len; i+=BPL) {
            word_t val = 0;
            fprintf(outfile, "0x%.4x:", pos+i);
            for (j = 0; j < BPL; j+= 4) {
                get_word_val(m, pos+i+j, &val);
                fprintf(outfile, " %.8x", val);
            }
        }
    }
}

mem_t init_reg()
{
    return init_naive_mem(32);
}

void free_reg(mem_t r)
{
    free_mem(r);
}

mem_t copy_reg(mem_t oldr)
{
    return copy_mem(oldr);
}

bool_t diff_reg(mem_t oldr, mem_t newr, FILE *outfile)
{
    word_t pos;
    int len = oldr->len;
    bool_t diff = FALSE;
    if (newr->len < len)
        len = newr->len;
    for (pos = 0; (!diff || outfile) && pos < len; pos += 4) {
        word_t ov = 0;
        word_t nv = 0;
        get_word_val(oldr, pos, &ov);
        get_word_val(newr, pos, &nv);
        if (nv != ov) {
            diff = TRUE;
            if (outfile)
                fprintf(outfile, "%s:\t0x%.8x\t0x%.8x\n",
                        reg_table[pos/4].name, ov, nv);
        }
    }
    return diff;
}

word_t get_reg_val(mem_t r, reg_id_t id)
{
    word_t val = 0;
    if (id >= REG_NONE)
        return 0;
    get_word_val(r,id*4, &val);
    return val;
}

void set_reg_val(mem_t r, reg_id_t id, word_t val)
{
    if (id < REG_NONE) {
        set_word_val(r,id*4,val);
#ifdef HAS_GUI
        if (gui_mode) {
            signal_register_update(id, val);
        }
#endif /* HAS_GUI */
    }
}

void dump_reg(FILE *outfile, mem_t r) {
    reg_id_t id;
    for (id = 0; reg_valid(id); id++) {
        fprintf(outfile, "   %s  ", reg_table[id].name);
    }
    fprintf(outfile, "\n");
    for (id = 0; reg_valid(id); id++) {
        word_t val = 0;
        get_word_val(r, id*4, &val);
        fprintf(outfile, " %x", val);
    }
    fprintf(outfile, "\n");
}

struct {
    char symbol;
    int id;
} alu_table[A_NONE+1] = 
{
    {'+',   A_ADD},
    {'-',   A_SUB},
    {'&',   A_AND},
    {'^',   A_XOR},
    {'?',   A_NONE}
};

char op_name(alu_t op)
{
    if (op < A_NONE)
        return alu_table[op].symbol;
    else
        return alu_table[A_NONE].symbol;
}

word_t compute_alu(alu_t op, word_t argA, word_t argB)
{
    word_t val;
    switch(op) {
        case A_ADD:
            val = argA+argB;
            break;
        case A_SUB:
            val = argB-argA;
            break;
        case A_AND:
            val = argA&argB;
            break;
        case A_XOR:
            val = argA^argB;
            break;
        default:
            val = 0;
    }
    return val;
}

cc_t compute_cc(alu_t op, word_t argA, word_t argB)
{
    word_t val = compute_alu(op, argA, argB);
    bool_t zero = (val == 0);
    bool_t sign = ((int)val < 0);
    bool_t ovf;
    switch(op) {
        case A_ADD:
            ovf = (((int) argA < 0) == ((int) argB < 0)) &&
                (((int) val < 0) != ((int) argA < 0));
            break;
        case A_SUB:
            ovf = (((int) argA > 0) == ((int) argB < 0)) &&
                (((int) val < 0) != ((int) argB < 0));
            break;
        case A_AND:
        case A_XOR:
            ovf = FALSE;
            break;
        default:
            ovf = FALSE;
    }
    return PACK_CC(zero,sign,ovf);

}

char *cc_names[8] = {
    "Z=0 S=0 O=0",
    "Z=0 S=0 O=1",
    "Z=0 S=1 O=0",
    "Z=0 S=1 O=1",
    "Z=1 S=0 O=0",
    "Z=1 S=0 O=1",
    "Z=1 S=1 O=0",
    "Z=1 S=1 O=1"};

char *cc_name(cc_t c)
{
    int ci = c;
    if (ci < 0 || ci > 7)
        return "???????????";
    else
        return cc_names[c];
}

/* Status types */

char *stat_names[] = { "BUB", "AOK", "HLT", "ADR", "INS", "PIP" };

char *stat_name(stat_t e)
{
    if (e < 0 || e > STAT_PIP)
        return "Invalid Status";
    return stat_names[e];
}

/**************** Implementation of ISA model ************************/

state_ptr new_state(int memlen)
{
    state_ptr result = (state_ptr) malloc(sizeof(state_rec));
    result->pc = 0;
    result->r = init_reg();
    result->m = init_mem(memlen);
    result->cc = DEFAULT_CC;
    return result;
}

void free_state(state_ptr s)
{
    free_reg(s->r);
    free_mem(s->m);
    free((void *) s);
}

state_ptr copy_state(state_ptr s) {
    state_ptr result = (state_ptr) malloc(sizeof(state_rec));
    result->pc = s->pc;
    result->r = copy_reg(s->r);
    result->m = copy_mem(s->m);
    result->cc = s->cc;
    return result;
}

bool_t diff_state(state_ptr olds, state_ptr news, FILE *outfile) {
    bool_t diff = FALSE;

    if (olds->pc != news->pc) {
        diff = TRUE;
        if (outfile) {
            fprintf(outfile, "pc:\t0x%.8x\t0x%.8x\n", olds->pc, news->pc);
        }
    }
    if (olds->cc != news->cc) {
        diff = TRUE;
        if (outfile) {
            fprintf(outfile, "cc:\t%s\t%s\n", cc_name(olds->cc), cc_name(news->cc));
        }
    }
    if (diff_reg(olds->r, news->r, outfile))
        diff = TRUE;
    if (diff_mem(olds->m, news->m, outfile))
        diff = TRUE;
    return diff;
}


/* Branch logic */
bool_t cond_holds(cc_t cc, cond_t bcond) {
    bool_t zf = GET_ZF(cc);
    bool_t sf = GET_SF(cc);
    bool_t of = GET_OF(cc);
    bool_t jump = FALSE;

    switch(bcond) {
        case C_YES:
            jump = TRUE;
            break;
        case C_LE:
            jump = (sf^of)|zf;
            break;
        case C_L:
            jump = sf^of;
            break;
        case C_E:
            jump = zf;
            break;
        case C_NE:
            jump = zf^1;
            break;
        case C_GE:
            jump = sf^of^1;
            break;
        case C_G:
            jump = (sf^of^1)&(zf^1);
            break;
        default:
            jump = FALSE;
            break;
    }
    return jump;
}


/* Execute single instruction.  Return status. */
stat_t step_state(state_ptr s, FILE *error_file)
{
    word_t argA, argB;
    byte_t byte0 = 0;
    byte_t byte1 = 0;
    itype_t hi0;
    alu_t  lo0;
    reg_id_t hi1 = REG_NONE;
    reg_id_t lo1 = REG_NONE;
    bool_t ok1 = TRUE;
    word_t cval = 0;
    word_t okc = TRUE;
    word_t val, dval;
    bool_t need_regids;
    bool_t need_imm;
    word_t ftpc = s->pc;  /* Fall-through PC */

    if (!get_byte_val(s->m, ftpc, &byte0)) {
        if (error_file)
            fprintf(error_file,
                    "PC = 0x%x, Invalid instruction address\n", s->pc);
        return STAT_ADR;
    }
    ftpc++;

    hi0 = HI4(byte0);
    lo0 = LO4(byte0);

    need_regids =
        (hi0 == I_RRMOVL || hi0 == I_ALU || hi0 == I_PUSHL ||
         hi0 == I_POPL || hi0 == I_IRMOVL || hi0 == I_RMMOVL ||
         hi0 == I_MRMOVL || hi0 == I_IADDL || hi0 == I_SWAP);

    if (need_regids) {
        ok1 = get_byte_val(s->m, ftpc, &byte1);
        ftpc++;
        hi1 = HI4(byte1);
        lo1 = LO4(byte1);
    }

    need_imm =
        (hi0 == I_IRMOVL || hi0 == I_RMMOVL || hi0 == I_MRMOVL ||
         hi0 == I_JMP || hi0 == I_CALL || hi0 == I_IADDL || hi0 == I_SWAP);

    if (need_imm) {
        okc = get_word_val(s->m, ftpc, &cval);
        ftpc += 4;
    }

    switch (hi0) {
        case I_NOP:
            s->pc = ftpc;
            break;
        case I_HALT:
            return STAT_HLT;
            break;
        case I_RRMOVL:  /* Both unconditional and conditional moves */
            if (!ok1) {
                if (error_file)
                    fprintf(error_file,
                            "PC = 0x%x, Invalid instruction address\n", s->pc);
                return STAT_ADR;
            }
            if (!reg_valid(hi1)) {
                if (error_file)
                    fprintf(error_file,
                            "PC = 0x%x, Invalid register ID 0x%.1x\n",
                            s->pc, hi1);
                return STAT_INS;
            }
            if (!reg_valid(lo1)) {
                if (error_file)
                    fprintf(error_file,
                            "PC = 0x%x, Invalid register ID 0x%.1x\n",
                            s->pc, lo1);
                return STAT_INS;
            }
            val = get_reg_val(s->r, hi1);
            if (cond_holds(s->cc, lo0))
                set_reg_val(s->r, lo1, val);
            s->pc = ftpc;
            break;
        case I_IRMOVL:
            if (!ok1) {
                if (error_file)
                    fprintf(error_file,
                            "PC = 0x%x, Invalid instruction address\n", s->pc);
                return STAT_ADR;
            }
            if (!okc) {
                if (error_file)
                    fprintf(error_file,
                            "PC = 0x%x, Invalid instruction address",
                            s->pc);
                return STAT_INS;
            }
            if (!reg_valid(lo1)) {
                if (error_file)
                    fprintf(error_file,
                            "PC = 0x%x, Invalid register ID 0x%.1x\n",
                            s->pc, lo1);
                return STAT_INS;
            }
            set_reg_val(s->r, lo1, cval);
            s->pc = ftpc;
            break;
        case I_RMMOVL:
            if (!ok1) {
                if (error_file)
                    fprintf(error_file,
                            "PC = 0x%x, Invalid instruction address\n", s->pc);
                return STAT_ADR;
            }
            if (!okc) {
                if (error_file)
                    fprintf(error_file,
                            "PC = 0x%x, Invalid instruction address\n", s->pc);
                return STAT_INS;
            }
            if (!reg_valid(hi1)) {
                if (error_file)
                    fprintf(error_file,
                            "PC = 0x%x, Invalid register ID 0x%.1x\n",
                            s->pc, hi1);
                return STAT_INS;
            }
            if (reg_valid(lo1)) 
                cval += get_reg_val(s->r, lo1);
            val = get_reg_val(s->r, hi1);
            if (!set_word_val(s->m, cval, val)) {
                if (error_file)
                    fprintf(error_file,
                            "PC = 0x%x, Invalid data address 0x%x\n",
                            s->pc, cval);
                return STAT_ADR;
            }
            s->pc = ftpc;
            break;
        case I_MRMOVL:
            if (!ok1) {
                if (error_file)
                    fprintf(error_file,
                            "PC = 0x%x, Invalid instruction address\n", s->pc);
                return STAT_ADR;
            }
            if (!okc) {
                if (error_file)
                    fprintf(error_file,
                            "PC = 0x%x, Invalid instruction addres\n", s->pc);
                return STAT_INS;
            }
            if (!reg_valid(hi1)) {
                if (error_file)
                    fprintf(error_file,
                            "PC = 0x%x, Invalid register ID 0x%.1x\n",
                            s->pc, hi1);
                return STAT_INS;
            }
            if (reg_valid(lo1)) 
                cval += get_reg_val(s->r, lo1);
            if (!get_word_val(s->m, cval, &val))
                return STAT_ADR;
            set_reg_val(s->r, hi1, val);
            s->pc = ftpc;
            break;
        case I_ALU:
            if (!ok1) {
                if (error_file)
                    fprintf(error_file,
                            "PC = 0x%x, Invalid instruction address\n", s->pc);
                return STAT_ADR;
            }
            argA = get_reg_val(s->r, hi1);
            argB = get_reg_val(s->r, lo1);
            val = compute_alu(lo0, argA, argB);
            set_reg_val(s->r, lo1, val);
            s->cc = compute_cc(lo0, argA, argB);
            s->pc = ftpc;
            break;
        case I_JMP:
            if (!ok1) {
                if (error_file)
                    fprintf(error_file,
                            "PC = 0x%x, Invalid instruction address\n", s->pc);
                return STAT_ADR;
            }
            if (!okc) {
                if (error_file)
                    fprintf(error_file,
                            "PC = 0x%x, Invalid instruction address\n", s->pc);
                return STAT_ADR;
            }
            if (cond_holds(s->cc, lo0))
                s->pc = cval;
            else
                s->pc = ftpc;
            break;
        case I_CALL:
            if (!ok1) {
                if (error_file)
                    fprintf(error_file,
                            "PC = 0x%x, Invalid instruction address\n", s->pc);
                return STAT_ADR;
            }
            if (!okc) {
                if (error_file)
                    fprintf(error_file,
                            "PC = 0x%x, Invalid instruction address\n", s->pc);
                return STAT_ADR;
            }
            val = get_reg_val(s->r, REG_ESP) - 4;
            set_reg_val(s->r, REG_ESP, val);
            if (!set_word_val(s->m, val, ftpc)) {
                if (error_file)
                    fprintf(error_file,
                            "PC = 0x%x, Invalid stack address 0x%x\n", s->pc, val);
                return STAT_ADR;
            }
            s->pc = cval;
            break;
        case I_RET:
            /* Return Instruction.  Pop address from stack */
            dval = get_reg_val(s->r, REG_ESP);
            if (!get_word_val(s->m, dval, &val)) {
                if (error_file)
                    fprintf(error_file,
                            "PC = 0x%x, Invalid stack address 0x%x\n",
                            s->pc, dval);
                return STAT_ADR;
            }
            set_reg_val(s->r, REG_ESP, dval + 4);
            s->pc = val;
            break;
        case I_PUSHL:
            if (!ok1) {
                if (error_file)
                    fprintf(error_file,
                            "PC = 0x%x, Invalid instruction address\n", s->pc);
                return STAT_ADR;
            }
            if (!reg_valid(hi1)) {
                if (error_file)
                    fprintf(error_file,
                            "PC = 0x%x, Invalid register ID 0x%.1x\n", s->pc, hi1);
                return STAT_INS;
            }
            val = get_reg_val(s->r, hi1);
            dval = get_reg_val(s->r, REG_ESP) - 4;
            set_reg_val(s->r, REG_ESP, dval);
            if  (!set_word_val(s->m, dval, val)) {
                if (error_file)
                    fprintf(error_file,
                            "PC = 0x%x, Invalid stack address 0x%x\n", s->pc, dval);
                return STAT_ADR;
            }
            s->pc = ftpc;
            break;
        case I_POPL:
            if (!ok1) {
                if (error_file)
                    fprintf(error_file,
                            "PC = 0x%x, Invalid instruction address\n", s->pc);
                return STAT_ADR;
            }
            if (!reg_valid(hi1)) {
                if (error_file)
                    fprintf(error_file,
                            "PC = 0x%x, Invalid register ID 0x%.1x\n", s->pc, hi1);
                return STAT_INS;
            }
            dval = get_reg_val(s->r, REG_ESP);
            set_reg_val(s->r, REG_ESP, dval+4);
            if (!get_word_val(s->m, dval, &val)) {
                if (error_file)
                    fprintf(error_file,
                            "PC = 0x%x, Invalid stack address 0x%x\n",
                            s->pc, dval);
                return STAT_ADR;
            }
            set_reg_val(s->r, hi1, val);
            s->pc = ftpc;
            break;
        case I_LEAVE:
            dval = get_reg_val(s->r, REG_EBP);
            set_reg_val(s->r, REG_ESP, dval+4);
            if (!get_word_val(s->m, dval, &val)) {
                if (error_file)
                    fprintf(error_file,
                            "PC = 0x%x, Invalid stack address 0x%x\n",
                            s->pc, dval);
                return STAT_ADR;
            }
            set_reg_val(s->r, REG_EBP, val);
            s->pc = ftpc;
            break;
        case I_IADDL:
            if (!ok1) {
                if (error_file)
                    fprintf(error_file,
                            "PC = 0x%x, Invalid instruction address\n", s->pc);
                return STAT_ADR;
            }
            if (!okc) {
                if (error_file)
                    fprintf(error_file,
                            "PC = 0x%x, Invalid instruction address",
                            s->pc);
                return STAT_INS;
            }
            if (!reg_valid(lo1)) {
                if (error_file)
                    fprintf(error_file,
                            "PC = 0x%x, Invalid register ID 0x%.1x\n",
                            s->pc, lo1);
                return STAT_INS;
            }
            argB = get_reg_val(s->r, lo1);
            val = argB + cval;
            set_reg_val(s->r, lo1, val);
            s->cc = compute_cc(A_ADD, cval, argB);
            s->pc = ftpc;
            break;
        // I_SWAP added
        // swap (reg that stores val) (reg that stores mem addr)
        case I_SWAP:
            if (!ok1) {
                if (error_file)
                    fprintf(error_file,
                            "PC = 0x%x, Invalid instruction address\n", s->pc);
                return STAT_ADR;
            }
            if (!okc) {
                if (error_file)
                    fprintf(error_file,
                            "PC = 0x%x, Invalid instruction address\n", s->pc);
                return STAT_INS;
            }
            if (!reg_valid(hi1)) {
                if (error_file)
                    fprintf(error_file,
                            "PC = 0x%x, Invalid register ID 0x%.1x\n",
                            s->pc, hi1);
                return STAT_INS;
            }
            if (reg_valid(lo1)) 
                cval += get_reg_val(s->r, lo1);
            val = get_reg_val(s->r, hi1);
            if (!swap_word_val(s->m, cval, &val)) {
                if (error_file)
                    fprintf(error_file,
                            "PC = 0x%x, Invalid data address 0x%x\n",
                            s->pc, cval);
                return STAT_ADR;
            }
            set_reg_val(s->r, hi1, val);
            s->pc = ftpc;
            break;
        default:
            if (error_file)
                fprintf(error_file,
                        "PC = 0x%x, Invalid instruction %.2x\n", s->pc, byte0);
            return STAT_INS;
    }
    return STAT_AOK;
}
