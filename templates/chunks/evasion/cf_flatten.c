// chunk: evasion/cf_flatten
// depends: (none)
// provides: cf_dispatch
// headers: windows.h
// risk: none
// note: Control flow flattening — provides a switch-case dispatch loop that
//       obscures the true execution order. Instead of sequential code, each
//       "basic block" is a case in a switch statement driven by a state variable.
//       This defeats pattern-matching on control flow graphs and makes
//       decompilation output significantly harder to analyze.

#ifndef CHUNK_CF_FLATTEN
#define CHUNK_CF_FLATTEN

#include <windows.h>

typedef int (*cf_block_fn)(void *ctx);

#define CF_MAX_BLOCKS 32

typedef struct {
    cf_block_fn blocks[CF_MAX_BLOCKS];
    int transitions[CF_MAX_BLOCKS]; /* next state after each block */
    int count;
    int entry_state;
    int exit_state;
} CF_DISPATCHER;

static CF_DISPATCHER _cf_disp = {0};

static int cf_add_block(cf_block_fn fn, int next_state) {
    if (_cf_disp.count >= CF_MAX_BLOCKS) return -1;
    int idx = _cf_disp.count;
    _cf_disp.blocks[idx] = fn;
    _cf_disp.transitions[idx] = next_state;
    _cf_disp.count++;
    return idx;
}

static void cf_set_entry(int state) { _cf_disp.entry_state = state; }
static void cf_set_exit(int state) { _cf_disp.exit_state = state; }

/*
 * cf_dispatch: Run all registered blocks through the flattened dispatch loop.
 * Execution order is determined by the transition table, not code layout.
 */
static int cf_dispatch(void *ctx) {
    volatile int state = _cf_disp.entry_state;
    volatile int iterations = 0;
    int max_iter = _cf_disp.count * 3;

    while (state != _cf_disp.exit_state && iterations < max_iter) {
        iterations++;

        /* Add entropy to state variable to confuse pattern matching */
        volatile int actual_state = state;

        switch (actual_state) {
            case 0:  if (_cf_disp.blocks[0])  _cf_disp.blocks[0](ctx);  state = _cf_disp.transitions[0];  break;
            case 1:  if (_cf_disp.blocks[1])  _cf_disp.blocks[1](ctx);  state = _cf_disp.transitions[1];  break;
            case 2:  if (_cf_disp.blocks[2])  _cf_disp.blocks[2](ctx);  state = _cf_disp.transitions[2];  break;
            case 3:  if (_cf_disp.blocks[3])  _cf_disp.blocks[3](ctx);  state = _cf_disp.transitions[3];  break;
            case 4:  if (_cf_disp.blocks[4])  _cf_disp.blocks[4](ctx);  state = _cf_disp.transitions[4];  break;
            case 5:  if (_cf_disp.blocks[5])  _cf_disp.blocks[5](ctx);  state = _cf_disp.transitions[5];  break;
            case 6:  if (_cf_disp.blocks[6])  _cf_disp.blocks[6](ctx);  state = _cf_disp.transitions[6];  break;
            case 7:  if (_cf_disp.blocks[7])  _cf_disp.blocks[7](ctx);  state = _cf_disp.transitions[7];  break;
            case 8:  if (_cf_disp.blocks[8])  _cf_disp.blocks[8](ctx);  state = _cf_disp.transitions[8];  break;
            case 9:  if (_cf_disp.blocks[9])  _cf_disp.blocks[9](ctx);  state = _cf_disp.transitions[9];  break;
            case 10: if (_cf_disp.blocks[10]) _cf_disp.blocks[10](ctx); state = _cf_disp.transitions[10]; break;
            case 11: if (_cf_disp.blocks[11]) _cf_disp.blocks[11](ctx); state = _cf_disp.transitions[11]; break;
            case 12: if (_cf_disp.blocks[12]) _cf_disp.blocks[12](ctx); state = _cf_disp.transitions[12]; break;
            case 13: if (_cf_disp.blocks[13]) _cf_disp.blocks[13](ctx); state = _cf_disp.transitions[13]; break;
            case 14: if (_cf_disp.blocks[14]) _cf_disp.blocks[14](ctx); state = _cf_disp.transitions[14]; break;
            case 15: if (_cf_disp.blocks[15]) _cf_disp.blocks[15](ctx); state = _cf_disp.transitions[15]; break;
            default: state = _cf_disp.exit_state; break;
        }
    }

    return (state == _cf_disp.exit_state) ? 1 : 0;
}

#endif
