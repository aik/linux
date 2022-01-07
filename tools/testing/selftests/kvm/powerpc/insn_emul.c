// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE /* for program_invocation_short_name */
#include <pthread.h>
#include <stdio.h>
#include <signal.h>

#define DEBUG
#include "kvm_util.h"
#include "test_util.h"

#define H_PUT_TERM_CHAR		0x58
#define TEST_VAL		0x1122334455667788
#define TEST_VALHI		0xAABBCCDDEEFF
#define PASS_VAL		0XDEADBEEF
#define FAIL_VAL		0X2BADD00D
#define MMIO_ADDR		0x100000000000ULL

extern uint64_t hcall(uint64_t nr, ...);

struct kvm_vm *vm;

typedef struct {
	uint64_t val, valhi;
} test128;

/*
 * Call the hypervisor to write a character to the console. KVM does
 * not handle this hypercall so it goes out to userspace. Which in
 * this case is the vcpu_worker() below.
*/
static inline void put_str(const char *s)
{
	while (*s) {
		hcall(H_PUT_TERM_CHAR, 0, 1, cpu_to_be64(*s));
		++s;
	}
}

static inline void put_hex(uint64_t n)
{
	int i;
	char *p = (char *) &n;
	const char dig[] = "0123456789ABCDEF";

	for (i = sizeof(n) - 1; i >= 0; --i) {
		hcall(H_PUT_TERM_CHAR, 0, 1, cpu_to_be64(dig[p[i] >> 4]));
		hcall(H_PUT_TERM_CHAR, 0, 1, cpu_to_be64(dig[p[i] & 0xf]));
	}
}

static bool check_insns(test128 *v, bool swap, const char *msg)
{
	bool ret = false;

	put_hex(v->valhi);
	put_hex(v->val);
	put_str(": ");
	put_str(msg);
	if (!swap && v->valhi == TEST_VALHI && v->val == TEST_VAL) {
		put_str(" => passed\n");
	} else if (swap && v->val == TEST_VALHI && v->valhi == TEST_VAL) {
		put_str(" => passed (swapped)\n");
	} else {
		put_str(" => FAILED\n");
		ret = true;
	}
	v->valhi = v->val = 0;

	return ret;
}

static void guest_code(uint64_t *ptr, uint64_t *mmio_addr)
{
	bool failed = false;
	test128 v __attribute__((aligned(16)));

	GUEST_ASSERT(ptr);
	GUEST_ASSERT(mmio_addr);
#if 0
	put_hex((uint64_t)ptr);
	put_hex((uint64_t)&v);
	put_hex((uint64_t)mmio_addr);
#endif
	v.valhi = v.val = 0x1234;

	asm volatile("lvx %0, 0, %1" : "=v" (v) : "r" (ptr));
	failed |= check_insns(&v, false, "lvx (VMX 128) mem");

	asm volatile("lvx %0, 0, %1" : "=v" (v) : "r" (mmio_addr));
	failed |= check_insns(&v, false, "lvx (VMX 128) mmio");

	asm volatile("lxv %0, %1" : "=wa" (v) : "m" (*ptr));
	failed |= check_insns(&v, false, "lxv (VSX 128) mem");

#if 0
	/*
	 * KVM does not emulate VSX 16 bytes though and there is hardly
	 * a point in implementing it now as VMX works.
	 */
	asm volatile("lxv %0, %1" : "=wa" (v) : "m" (mmio_addr));
	failed |= check_insns(&v, false, "lxv (VSX 128) mmio");
#endif
#if 0
	/*
	 * This is good if we want to avoid -mvsx -maltivec and have
	 * complete control over our asm.
	 */
	asm volatile(
		"lvx 0, 0, %1\n"
		"stvx 0, 0, %0"
		: : "r" (&v), "r" (ptr) : "memory");
	failed |= check_insns(&v, false, "lvx+stvx mem");

	asm volatile(
		"lvx 0, 0, %1\n"
		"stvx 0, 0, %0"
		: : "b" (&v), "b" (mmio_addr) : "memory");
	failed |= check_insns(&v, false, "lvx mmio");
#endif
#if 0
	/*
	 * GCC only enables lq generation on big endian systems and hi/lo parts
	 * are not swapped in LE mode (P10's plq does not have this issue) so
	 * this one should not work at all but it does by accident.
	 */
	asm volatile(
		"lis 20, 0xAA\n"
		"lis 21, 0xBB\n"
		"lq 20, %2\n"
		"mr %0, 20\n"
		"mr %1, 21\n"
		: "=&r" (v.valhi), "=&r" (v.val)
		: "wQ" (*(__int128 *)ptr)
		: "20", "21");

	failed |= check_insns(&v, false, "lq mem2");
#endif
	asm volatile("lq %0, %1" : "=&r" (v) : "m" (*ptr));
	failed |= check_insns(&v, true, "lq mem1");
#if 0
	/*
	 * After all "lq" is not implemented as the comment
	 * for kvmppc_emulate_loadstore() says.
	 */
	asm volatile(
		"lis 20, 0xCC\n"
		"lis 21, 0xDD\n"
		"lq 20, %2\n"
		"mr %0, 20\n"
		"mr %1, 21\n"
		: "=&r" (v.valhi), "=&r" (v.val)
		: "wQ" (*(__int128 *)mmio_addr)
		: "20", "21");
	failed |= check_insns(&v, false, "lq mmio");
#endif
#if 0
	/* POWER10 min */
	asm volatile("plq %0, 0(%1)" : "=r" (v1) : "b" (ptr));
#endif
	*ptr = failed ? FAIL_VAL : PASS_VAL;

	/* Signal we're done */
	GUEST_DONE();
}

static bool guest_done(struct kvm_vm *vm)
{
	struct ucall uc;
	bool done;

	switch (get_ucall(vm, 0, &uc)) {
	case UCALL_ABORT:
		TEST_FAIL("%s at %s:%ld", (const char *)uc.args[0],
			  __FILE__, uc.args[1]);
		/* not reached */
	case UCALL_DONE:
		done = true;
		break;
	default:
		done = false;
		break;
	}

	return done;
}

static void *vcpu_worker(void *data)
{
	struct kvm_vm *vm = data;
	struct kvm_run *run;
	uint64_t *hva;
	static test128 test_buf __attribute__((aligned(16))) = {
		TEST_VAL,
		TEST_VALHI,
		};
	vm_vaddr_t mmio_addr = vm_vaddr_unused_gap(vm, sizeof(test_buf), KVM_UTIL_MIN_MMIO_VADDR);

	virt_pg_map(vm, mmio_addr, MMIO_ADDR);

	vcpu_args_set(vm, 0, 2, &test_buf, mmio_addr);

	run = vcpu_state(vm, 0);
	while (1) {
		vcpu_run(vm, 0);

		if (guest_done(vm))
			break;

		switch (run->exit_reason) {
		case KVM_EXIT_MMIO:
			printf("KVM_EXIT_MMIO %llx %u: ", run->mmio.phys_addr, run->mmio.len);

			if ((run->mmio.phys_addr & ~(uint64_t)(MIN_PAGE_SIZE - 1)) == MMIO_ADDR) {
				unsigned off = run->mmio.phys_addr & (MIN_PAGE_SIZE - 1);

				if (off <= sizeof(test_buf) && run->mmio.len <= sizeof(run->mmio.data)) {
					printf(" <= %lx", *(uint64_t *) ((char *)&test_buf + off));
					memcpy(run->mmio.data, (char *)&test_buf + off, run->mmio.len);
				}
			}
			printf("\n");
			break;
		case KVM_EXIT_PAPR_HCALL:
			if (run->papr_hcall.nr == H_PUT_TERM_CHAR) {
				char c = be64_to_cpu(run->papr_hcall.args[2]);
				pr_debug("%c", c);
			}
			break;
		default:
			printf("exit reason: %s\n", exit_reason_str(run->exit_reason));
			break;
		}
	}

	hva = addr_gva2hva(vm, (vm_vaddr_t)&test_buf);
	TEST_ASSERT(*hva != FAIL_VAL,
		    "Guest failed to read test value at gva %p = %lx", &test_buf, *hva);
	TEST_ASSERT(*hva == PASS_VAL,
		    "Guest failed to write test value to gva %p = %lx", &test_buf, *hva);

	pr_debug("PASS\n");

	return NULL;
}

void dump_vm(int sig)
{
	vm_dump(stderr, vm, 2);
	exit(1);
}

int main(int argc, char *argv[])
{
	pthread_t vcpu_thread;

	signal(SIGINT, dump_vm);

	/*
	 * Do not buffer stdout so we can implement put_str without
	 * flushing.
	 */
	setbuf(stdout, NULL);

	vm = vm_create_default(0, 0, guest_code);
	pthread_create(&vcpu_thread, NULL, vcpu_worker, vm);

	pthread_join(vcpu_thread, NULL);
	kvm_vm_free(vm);

	return 0;
}
