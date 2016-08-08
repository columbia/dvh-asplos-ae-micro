/*
 * Test the framework itself. These tests confirm that setup works.
 *
 * Copyright (C) 2014, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <libcflat.h>
#include <util.h>
#include <devicetree.h>
#include <asm/setup.h>
#include <asm/ptrace.h>
#include <asm/asm-offsets.h>
#include <asm/processor.h>
#include <asm/thread_info.h>
#include <asm/psci.h>
#include <asm/smp.h>
#include <asm/cpumask.h>
#include <asm/barrier.h>
#include <asm/io.h>

#define ARM_MICRO_TEST 1

static bool count_cycles = true;
static void *mmio_read_user_addr = (void*) 0x0a000008;
static void *vgic_dist_addr = (void*) 0x08000000;
static void *vgic_cpu_addr = (void*) 0x08010000;
static const int sgi_irq = 1;

#define GICC_EOIR               0x00000010
#define GOAL (1ULL << 28)

#define ARR_SIZE(_x) ((int)(sizeof(_x) / sizeof(_x[0])))
#define for_each_test(_iter, _tests, _tmp) \
	for (_tmp = 0, _iter = _tests; \
			_tmp < ARR_SIZE(_tests); \
			_tmp++, _iter++)

#define CYCLE_COUNT(c1, c2) \
	(((c1) > (c2) || ((c1) == (c2) && count_cycles)) ? 0 : (c2) - (c1))


static void check_setup(int argc, char **argv)
{
	int nr_tests = 0, len, i;
	long val;

	for (i = 0; i < argc; ++i) {

		len = parse_keyval(argv[i], &val);
		if (len == -1)
			continue;

		argv[i][len] = '\0';
		report_prefix_push(argv[i]);

		if (strcmp(argv[i], "mem") == 0) {

			phys_addr_t memsize = PHYS_END - PHYS_OFFSET;
			phys_addr_t expected = ((phys_addr_t)val)*1024*1024;

			report("size = %d MB", memsize == expected,
							memsize/1024/1024);
			++nr_tests;

		} else if (strcmp(argv[i], "smp") == 0) {

			report("nr_cpus = %d", nr_cpus == (int)val, nr_cpus);
			++nr_tests;
		}

		report_prefix_pop();
	}

	if (nr_tests < 2)
		report_abort("missing input");
}

static struct pt_regs expected_regs;
static bool und_works;
static bool svc_works;
#if defined(__arm__)
/*
 * Capture the current register state and execute an instruction
 * that causes an exception. The test handler will check that its
 * capture of the current register state matches the capture done
 * here.
 *
 * NOTE: update clobber list if passed insns needs more than r0,r1
 */
#define test_exception(pre_insns, excptn_insn, post_insns)	\
	asm volatile(						\
		pre_insns "\n"					\
		"mov	r0, %0\n"				\
		"stmia	r0, { r0-lr }\n"			\
		"mrs	r1, cpsr\n"				\
		"str	r1, [r0, #" xstr(S_PSR) "]\n"		\
		"mov	r1, #-1\n"				\
		"str	r1, [r0, #" xstr(S_OLD_R0) "]\n"	\
		"add	r1, pc, #8\n"				\
		"str	r1, [r0, #" xstr(S_R1) "]\n"		\
		"str	r1, [r0, #" xstr(S_PC) "]\n"		\
		excptn_insn "\n"				\
		post_insns "\n"					\
	:: "r" (&expected_regs) : "r0", "r1")

static bool check_regs(struct pt_regs *regs)
{
	unsigned i;

	/* exception handlers should always run in svc mode */
	if (current_mode() != SVC_MODE)
		return false;

	for (i = 0; i < ARRAY_SIZE(regs->uregs); ++i) {
		if (regs->uregs[i] != expected_regs.uregs[i])
			return false;
	}

	return true;
}

static void und_handler(struct pt_regs *regs)
{
	und_works = check_regs(regs);
}

static bool check_und(void)
{
	install_exception_handler(EXCPTN_UND, und_handler);

	/* issue an instruction to a coprocessor we don't have */
	test_exception("", "mcr p2, 0, r0, c0, c0", "");

	install_exception_handler(EXCPTN_UND, NULL);

	return und_works;
}

static void svc_handler(struct pt_regs *regs)
{
	u32 svc = *(u32 *)(regs->ARM_pc - 4) & 0xffffff;

	if (processor_mode(regs) == SVC_MODE) {
		/*
		 * When issuing an svc from supervisor mode lr_svc will
		 * get corrupted. So before issuing the svc, callers must
		 * always push it on the stack. We pushed it to offset 4.
		 */
		regs->ARM_lr = *(unsigned long *)(regs->ARM_sp + 4);
	}

	svc_works = check_regs(regs) && svc == 123;
}

static bool check_svc(void)
{
	install_exception_handler(EXCPTN_SVC, svc_handler);

	if (current_mode() == SVC_MODE) {
		/*
		 * An svc from supervisor mode will corrupt lr_svc and
		 * spsr_svc. We need to save/restore them separately.
		 */
		test_exception(
			"mrs	r0, spsr\n"
			"push	{ r0,lr }\n",
			"svc	#123\n",
			"pop	{ r0,lr }\n"
			"msr	spsr_cxsf, r0\n"
		);
	} else {
		test_exception("", "svc #123", "");
	}

	install_exception_handler(EXCPTN_SVC, NULL);

	return svc_works;
}
#elif defined(__aarch64__)

/*
 * Capture the current register state and execute an instruction
 * that causes an exception. The test handler will check that its
 * capture of the current register state matches the capture done
 * here.
 *
 * NOTE: update clobber list if passed insns needs more than x0,x1
 */
#define test_exception(pre_insns, excptn_insn, post_insns)	\
	asm volatile(						\
		pre_insns "\n"					\
		"mov	x1, %0\n"				\
		"ldr	x0, [x1, #" xstr(S_PSTATE) "]\n"	\
		"mrs	x1, nzcv\n"				\
		"orr	w0, w0, w1\n"				\
		"mov	x1, %0\n"				\
		"str	w0, [x1, #" xstr(S_PSTATE) "]\n"	\
		"mov	x0, sp\n"				\
		"str	x0, [x1, #" xstr(S_SP) "]\n"		\
		"adr	x0, 1f\n"				\
		"str	x0, [x1, #" xstr(S_PC) "]\n"		\
		"stp	 x2,  x3, [x1,  #16]\n"			\
		"stp	 x4,  x5, [x1,  #32]\n"			\
		"stp	 x6,  x7, [x1,  #48]\n"			\
		"stp	 x8,  x9, [x1,  #64]\n"			\
		"stp	x10, x11, [x1,  #80]\n"			\
		"stp	x12, x13, [x1,  #96]\n"			\
		"stp	x14, x15, [x1, #112]\n"			\
		"stp	x16, x17, [x1, #128]\n"			\
		"stp	x18, x19, [x1, #144]\n"			\
		"stp	x20, x21, [x1, #160]\n"			\
		"stp	x22, x23, [x1, #176]\n"			\
		"stp	x24, x25, [x1, #192]\n"			\
		"stp	x26, x27, [x1, #208]\n"			\
		"stp	x28, x29, [x1, #224]\n"			\
		"str	x30, [x1, #" xstr(S_LR) "]\n"		\
		"stp	 x0,  x1, [x1]\n"			\
	"1:"	excptn_insn "\n"				\
		post_insns "\n"					\
	:: "r" (&expected_regs) : "x0", "x1")

static bool check_regs(struct pt_regs *regs)
{
	unsigned i;

	/* exception handlers should always run in EL1 */
	if (current_level() != CurrentEL_EL1)
		return false;

	for (i = 0; i < ARRAY_SIZE(regs->regs); ++i) {
		if (regs->regs[i] != expected_regs.regs[i])
			return false;
	}

	regs->pstate &= 0xf0000000 /* NZCV */ | 0x3c0 /* DAIF */
			| PSR_MODE_MASK;

	return regs->sp == expected_regs.sp
		&& regs->pc == expected_regs.pc
		&& regs->pstate == expected_regs.pstate;
}

static enum vector check_vector_prep(void)
{
	unsigned long daif;

	if (is_user())
		return EL0_SYNC_64;

	asm volatile("mrs %0, daif" : "=r" (daif) ::);
	expected_regs.pstate = daif | PSR_MODE_EL1h;
	return EL1H_SYNC;
}

static void unknown_handler(struct pt_regs *regs, unsigned int esr __unused)
{
	und_works = check_regs(regs);
	regs->pc += 4;
}

static bool check_und(void)
{
	enum vector v = check_vector_prep();

	install_exception_handler(v, ESR_EL1_EC_UNKNOWN, unknown_handler);

	/* try to read an el2 sysreg from el0/1 */
	test_exception("", "mrs x0, sctlr_el2", "");

	install_exception_handler(v, ESR_EL1_EC_UNKNOWN, NULL);

	return und_works;
}

static void svc_handler(struct pt_regs *regs, unsigned int esr)
{
	u16 svc = esr & 0xffff;

	expected_regs.pc += 4;
	svc_works = check_regs(regs) && svc == 123;
}

static bool check_svc(void)
{
	enum vector v = check_vector_prep();

	install_exception_handler(v, ESR_EL1_EC_SVC64, svc_handler);

	test_exception("", "svc #123", "");

	install_exception_handler(v, ESR_EL1_EC_SVC64, NULL);

	return svc_works;
}
#endif

static void check_vectors(void *arg __unused)
{
	report("und", check_und());
	report("svc", check_svc());
	exit(report_summary());
}

static bool psci_check(void)
{
	const struct fdt_property *method;
	int node, len, ver;

	node = fdt_node_offset_by_compatible(dt_fdt(), -1, "arm,psci-0.2");
	if (node < 0) {
		printf("PSCI v0.2 compatibility required\n");
		return false;
	}

	method = fdt_get_property(dt_fdt(), node, "method", &len);
	if (method == NULL) {
		printf("bad psci device tree node\n");
		return false;
	}

	if (len < 4 || strcmp(method->data, "hvc") != 0) {
		printf("psci method must be hvc\n");
		return false;
	}

	ver = psci_invoke(PSCI_0_2_FN_PSCI_VERSION, 0, 0, 0);
	printf("PSCI version %d.%d\n", PSCI_VERSION_MAJOR(ver),
				       PSCI_VERSION_MINOR(ver));

	return true;
}

static cpumask_t smp_reported;
static void cpu_report(void)
{
	int cpu = smp_processor_id();

	report("CPU%d online", true, cpu);
	cpumask_set_cpu(cpu, &smp_reported);
	halt();
}

#if ARM_MICRO_TEST == 1
static uint64_t read_cc(void)
{
	uint64_t cc;
	if (!count_cycles)
		return 0;
	asm volatile(
		"isb\n"
		"mrs %0, PMCCNTR_EL0\n"
		"isb\n"
		: [reg] "=r" (cc)
		::
	);
	return cc;
}

static unsigned long hvc_test(void)
{
	unsigned long c1, c2;

	c1 = read_cc();
	asm volatile("mov w0, #0x4b000000; hvc #0");
	c2 = read_cc();
	return CYCLE_COUNT(c1, c2);
}

static void __noop(void)
{
}

static unsigned long noop_guest(void)
{
	unsigned long c1, c2;

	c1 = read_cc();
	__noop();
	c2 = read_cc();
	return CYCLE_COUNT(c1, c2);
}

static unsigned long mmio_read_user(void)
{
	unsigned long c1, c2;

	c1 = read_cc();
	readl(mmio_read_user_addr);
	c2 = read_cc();
	return CYCLE_COUNT(c1, c2);
}

static unsigned long mmio_read_vgic(void)
{
	unsigned long c1, c2;

	c1 = read_cc();
	readl(vgic_dist_addr + 0x8);
	c2 = read_cc();
	return CYCLE_COUNT(c1, c2);
}

static unsigned long eoi_test(void)
{
	unsigned long c1, c2;

	unsigned long val = 1023; /* spurious IDs, writes to EOI are ignored */
	c1 = read_cc();
	writel(val, vgic_cpu_addr + GICC_EOIR);
	c2 = read_cc();
	return CYCLE_COUNT(c1, c2);
}

struct exit_test {
	char *name;
	unsigned long (*test_fn)(void);
	bool run;
};

static struct exit_test available_tests[] = {
	{"hvc",                hvc_test,           true},
	{"noop_guest",         noop_guest,         true},
	{"mmio_read_user",     mmio_read_user,     true},
	{"mmio_read_vgic",     mmio_read_vgic,     true},
	//{ "ipi",                ipi_test,           false },
	{"eoi",                eoi_test,           true},
};

static void loop_test(struct exit_test *test)
{
	unsigned long i, iterations = 32;
	unsigned long sample, cycles;
	unsigned long long min = 0, max = 0;
	do {
		iterations *= 2;
		cycles = 0;
		for (i = 0; i < iterations; i++) {
			sample = test->test_fn();
			if (sample == 0 && count_cycles) {
				/* If something went wrong or we had an
				 * overflow, don't count that sample */
				iterations--;
				i--;
				//debug("cycle count overflow: %d\n", sample);
				continue;
			}
			cycles += sample;
			if (min == 0 || min > sample)
				min = sample;
			if (max < sample)
				max = sample;
		}
	} while (cycles < GOAL && count_cycles);
	printf("%s:\t avg %lu\t min %llu\t max %llu\n",
		test->name, cycles / iterations, min, max);
}

void kvm_unit_test(void)
{
	int i=0;
	struct exit_test *test;
	for_each_test(test, available_tests, i) {
		if (!test->run)
			continue;
		loop_test(test);
	}

	return;
}
#endif

int main(int argc, char **argv)
{
	report_prefix_push("selftest");

#if ARM_MICRO_TEST == 1
	kvm_unit_test();
	return 0;
#endif

	if (argc < 2)
		report_abort("no test specified");

	report_prefix_push(argv[1]);

	if (strcmp(argv[1], "setup") == 0) {

		check_setup(argc-2, &argv[2]);

	} else if (strcmp(argv[1], "vectors-kernel") == 0) {

		check_vectors(NULL);

	} else if (strcmp(argv[1], "vectors-user") == 0) {

		start_usr(check_vectors, NULL,
				(unsigned long)thread_stack_alloc());

	} else if (strcmp(argv[1], "smp") == 0) {

		int cpu;

		report("PSCI version", psci_check());

		for_each_present_cpu(cpu) {
			if (cpu == 0)
				continue;
			smp_boot_secondary(cpu, cpu_report);
		}

		cpumask_set_cpu(0, &smp_reported);
		while (!cpumask_full(&smp_reported))
			cpu_relax();
	} else {
		printf("Unknown subtest\n");
		abort();
	}

	return report_summary();
}
