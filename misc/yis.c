/* Instruction set simulator for Y86 Architecture */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "isa.h"

#define PAUSE

/* YIS never runs in GUI mode */
int gui_mode = 0;

void usage(char *pname)
{
    printf("Usage: %s code_file [max_steps]\n", pname);
    exit(0);
}

int main(int argc, char *argv[])
{
    FILE *code_file;
    int max_steps = 10000;

    srand(time(0));

    state_ptr s = new_state(MEM_SIZE);

    printf("state created.\n");

    mem_t saver = copy_reg(s->r);
    mem_t savem;
    int step = 0;

    printf("init done.\n");

    stat_t e = STAT_AOK;

    if (argc < 2 || argc > 3)
        usage(argv[0]);
    code_file = fopen(argv[1], "r");
    if (!code_file) {
        fprintf(stderr, "Can't open code file '%s'\n", argv[1]);
        exit(1);
    }

    printf("file opened.\n");

    if (!load_mem(s->m, code_file, 1)) {
        printf("Exiting\n");
        return 1;
    }

    printf("loading done.\n");

    savem = copy_mem(s->m);

    printf("mem copied.\n");

    if (argc > 2)
        max_steps = atoi(argv[2]);

    for (step = 0; step < max_steps && e == STAT_AOK; step++)
    {
        e = step_state(s, stdout);
        #ifdef PAUSE
        printf("step %d finished.\n", step);
        printf("private mem:\n");
        dump_memory(stdout, s->m, 0, 32);
        printf("\nshared mem:\n");
        dump_memory(stdout, s->m, MEM_SIZE, 32);
        printf("\n");
        getchar();
        #endif
    }

    printf("Stopped in %d steps at PC = 0x%x.  Status '%s', CC %s\n",
            step, s->pc, stat_name(e), cc_name(s->cc));

    printf("Changes to registers:\n");
    diff_reg(saver, s->r, stdout);

    printf("\nChanges to memory:\n");
    diff_mem(savem, s->m, stdout);

    free_state(s);
    free_reg(saver);
    free_mem(savem);

    return 0;
}
