#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>

#ifndef REG_EIP
#define REG_EIP 14
#endif

#define OP_SSE3_MOVSLDUP	0x0ff312
#define OP_SSE3_MOVSHDUP	0x0ff316
#define OP_SSE3_MOVDDUP		0x0ff212
#define OP_SSE3_ADDSUBPD	0x0f66d0
#define OP_SSE3_ADDSUBPS	0x0ff2d0
#define OP_SSE3_LDDQU		0x0ff2f0
#define OP_SSE3_HADDPD		0x0f667c
#define OP_SSE3_HSUBPD		0x0f667d
#define OP_SSE3_HADDPS		0x0ff27c
#define OP_SSE3_HSUBPS		0x0ff27d

#define OP_NOP		0x90

static int op_sse3_movsldup(ucontext_t *context, int instruction_len, unsigned char *data, unsigned char *new_instructions) {
	return(0);
}

static int have_sse3 = 1;

static void sse3_handler(int sig_nr, siginfo_t *info, void *p_context) {
	static int pagesize = 0;
	static int in_handler = 0;
	ucontext_t *context = p_context;
	unsigned char *instruction;
	unsigned char new_instructions[8] = {OP_NOP, OP_NOP, OP_NOP, OP_NOP, OP_NOP, OP_NOP, OP_NOP, OP_NOP};
	uint32_t opcode;
	int instruction_len;
	int has_replacement = 0;
	int mprot_ret;

	if (in_handler) {
		return;
	}

	in_handler = 1;

	if (sig_nr != SIGILL) {
		return;
	}

	if (!info) {
		return;
	}

	if (!context) {
		abort();
	}

	if (pagesize == 0) {
		pagesize = getpagesize();
	}

	instruction = (char *) context->uc_mcontext.gregs[REG_EIP];
	opcode = (instruction[1] << 16) | (instruction[0] << 8) | instruction[2];

//	printf("EIP = %p\n", instruction);
//	printf("Instr = %06x,%02x,%02x\n", opcode, instruction[1], instruction[3]);

	switch (opcode) {
		case OP_SSE3_MOVSLDUP:
			instruction_len = 4;

			has_replacement = op_sse3_movsldup(context, instruction_len - 3, instruction + 3, new_instructions);
			break;
		case OP_SSE3_MOVSHDUP:
			instruction_len = 4;
			break;
		case OP_SSE3_MOVDDUP:
			instruction_len = 4;
			break;
		case OP_SSE3_ADDSUBPD:
			instruction_len = 4;
			break;
		case OP_SSE3_ADDSUBPS:
			instruction_len = 4;
			break;
		case OP_SSE3_LDDQU:
			instruction_len = 8;
			break;
		case OP_SSE3_HADDPD:
			instruction_len = 4;
			break;
		case OP_SSE3_HSUBPD:
			instruction_len = 4;
			break;
		case OP_SSE3_HADDPS:
			instruction_len = 4;
			break;
		case OP_SSE3_HSUBPS:
			instruction_len = 4;
			break;
		default:
			abort();
	}

	/*
	 * Rewrite this so we can handle it faster next time.
	 */
	if (has_replacement) {
		mprot_ret = mprotect((void *) (((intptr_t) instruction) & ~(pagesize - 1)), pagesize, PROT_WRITE | PROT_READ | PROT_EXEC);
		if (mprot_ret < 0) {
			perror("mprotect");
		}

		memcpy(instruction, new_instructions, instruction_len);

		mprot_ret = mprotect((void *) (((intptr_t) instruction) & ~(pagesize - 1)), pagesize, PROT_READ | PROT_EXEC);
		if (mprot_ret < 0) {
			perror("mprotect");
		}
	}

	context->uc_mcontext.gregs[REG_EIP] += instruction_len;

	in_handler = 0;

	return;
}

#ifndef NO_SSE3_TEST
static void sse3_test_handler(int sig_nr, siginfo_t *info, void *p_context) {
	ucontext_t *context = p_context;

	if (sig_nr != SIGILL) {
		return;
	}

	if (!info) {
		return;
	}

	have_sse3 = 0;
	context->uc_mcontext.gregs[REG_EIP] += 4;

	return;
}

static void install_test_handler(void) {
	struct sigaction act;
	sigset_t masked;

	act.sa_sigaction = sse3_test_handler;
	act.sa_mask = masked;
	act.sa_flags = SA_SIGINFO;

	sigaction(SIGILL, &act, NULL);

	return;
}

static void uninstall_test_handler(void) {
	struct sigaction act;

	act.sa_handler = SIG_DFL;
	act.sa_flags = 0;

	sigaction(SIGILL, &act, NULL);

	return;
}
#endif

static void install_handler(void) {
	struct sigaction act;
	sigset_t masked;

	act.sa_sigaction = sse3_handler;
	act.sa_mask = masked;
	act.sa_flags = SA_SIGINFO;

	sigaction(SIGILL, &act, NULL);

	return;
}


static int __attribute__((constructor)) load_sse3_handler(void) {
#ifdef DEBUG
	printf("Trying to call some SSE3 instructions now...\n");
#endif

	install_test_handler();
	__asm__ ( "MOVSLDUP %xmm2,%xmm2 " );
	uninstall_test_handler();

	if (!have_sse3) {
#ifdef DEBUG
		printf("You do not have SSE3, installing handler.\n");
#endif
		install_handler();
	} else {
#ifdef DEBUG
		printf("You have SSE3, nothing will be done.\n");
#endif
	}

	return(0);
}
