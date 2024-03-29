#include "libcflat.h"
#include "smp.h"
#include "processor.h"
#include "atomic.h"
#include "pci.h"
#include "x86/vm.h"
#include "x86/desc.h"
#include "x86/acpi.h"
#include "measure.h"

struct test {
	void (*func)(void);
	const char *name;
	int (*valid)(void);
	int parallel;
	bool (*next)(struct test *);
	void (*pre_test)(void);
	void (*post_test)(void);
	int threshold;
};

#define GOAL (1ull << 30)

static int nr_cpus;

static void cpuid_test(void)
{
	asm volatile ("push %%"R "bx; cpuid; pop %%"R "bx"
		      : : : "eax", "ecx", "edx");
}

static void vmcall(void)
{
	unsigned long a = 0, b, c, d;

	asm volatile ("vmcall" : "+a"(a), "=b"(b), "=c"(c), "=d"(d));
}

#define MSR_TSC_ADJUST 0x3b
#define MSR_EFER 0xc0000080
#define EFER_NX_MASK            (1ull << 11)

#ifdef __x86_64__
static void mov_from_cr8(void)
{
	unsigned long cr8;

	asm volatile ("mov %%cr8, %0" : "=r"(cr8));
}

static void mov_to_cr8(void)
{
	unsigned long cr8 = 0;

	asm volatile ("mov %0, %%cr8" : : "r"(cr8));
}
#endif

static int is_smp(void)
{
	return cpu_count() > 1;
}

static void nop(void *junk)
{
}

bool inf_run;
static void inf(void *junk)
{
	int a = smp_id();
	int b;
	static int cnt = 0;
	printf("cpu %d goes to run\n", smp_id());

	inf_run = true;

	irq_enable();
	while (inf_run)
		;
}

static void ipi_pre_test(void)
{
	on_cpu_async(1, inf, 0);
}

static void ipi_post_test(void)
{
	inf_run = false;
}

static void ipi(void)
{
	on_cpu(1, nop, 0);
}

static void ipi_nowait_post_test(void)
{
	on_cpu_completion_wait(1);
}

static void ipi_nowait(void)
{
	on_cpu_sync_nowait_receive(1, nop, 0);
}

static void ipi_halt(void)
{
	unsigned long long t;

	on_cpu(1, nop, 0);
	t = rdtsc() + 2000;
	while (rdtsc() < t)
		;
}

int pm_tmr_blk;
static void inl_pmtimer(void)
{
    inl(pm_tmr_blk);
}

static void inl_nop_qemu(void)
{
    inl(0x1234);
}

static void inl_nop_kernel(void)
{
    inb(0x4d0);
}

static void outl_elcr_kernel(void)
{
    outb(0, 0x4d0);
}

static void mov_dr(void)
{
    asm volatile("mov %0, %%dr7" : : "r" (0x400L));
}

static void ple_round_robin(void)
{
	struct counter {
		volatile int n1;
		int n2;
	} __attribute__((aligned(64)));
	static struct counter counters[64] = { { -1, 0 } };
	int me = smp_id();
	int you;
	volatile struct counter *p = &counters[me];

	while (p->n1 == p->n2)
		asm volatile ("pause");

	p->n2 = p->n1;
	you = me + 1;
	if (you == nr_cpus)
		you = 0;
	++counters[you].n1;
}

static void rd_tsc_adjust_msr(void)
{
	rdmsr(MSR_TSC_ADJUST);
}

static void wr_tsc_adjust_msr(void)
{
	wrmsr(MSR_TSC_ADJUST, 0x0);
}

static struct pci_test {
	unsigned iobar;
	unsigned ioport;
	volatile void *memaddr;
	volatile void *mem;
	int test_idx;
	uint32_t data;
	uint32_t offset;
} pci_test = {
	.test_idx = -1
};

static void pci_mem_testb(void)
{
	*(volatile uint8_t *)pci_test.mem = pci_test.data;
}

static void pci_mem_testw(void)
{
	*(volatile uint16_t *)pci_test.mem = pci_test.data;
}

static void pci_mem_testl(void)
{
	*(volatile uint32_t *)pci_test.mem = pci_test.data;
}

static void pci_io_testb(void)
{
	outb(pci_test.data, pci_test.ioport);
}

static void pci_io_testw(void)
{
	outw(pci_test.data, pci_test.ioport);
}

static void pci_io_testl(void)
{
	outl(pci_test.data, pci_test.ioport);
}

static uint8_t ioreadb(unsigned long addr, bool io)
{
	if (io) {
		return inb(addr);
	} else {
		return *(volatile uint8_t *)addr;
	}
}

static uint32_t ioreadl(unsigned long addr, bool io)
{
	/* Note: assumes little endian */
	if (io) {
		return inl(addr);
	} else {
		return *(volatile uint32_t *)addr;
	}
}

static void iowriteb(unsigned long addr, uint8_t data, bool io)
{
	if (io) {
		outb(data, addr);
	} else {
		*(volatile uint8_t *)addr = data;
	}
}

static bool pci_next(struct test *test, unsigned long addr, bool io)
{
	int i;
	uint8_t width;

	if (!pci_test.memaddr) {
		test->func = NULL;
		return true;
	}
	pci_test.test_idx++;
	iowriteb(addr + offsetof(struct pci_test_dev_hdr, test),
		 pci_test.test_idx, io);
	width = ioreadb(addr + offsetof(struct pci_test_dev_hdr, width),
			io);
	switch (width) {
		case 1:
			test->func = io ? pci_io_testb : pci_mem_testb;
			break;
		case 2:
			test->func = io ? pci_io_testw : pci_mem_testw;
			break;
		case 4:
			test->func = io ? pci_io_testl : pci_mem_testl;
			break;
		default:
			/* Reset index for purposes of the next test */
			pci_test.test_idx = -1;
			test->func = NULL;
			return false;
	}
	pci_test.data = ioreadl(addr + offsetof(struct pci_test_dev_hdr, data),
				io);
	pci_test.offset = ioreadl(addr + offsetof(struct pci_test_dev_hdr,
						  offset), io);
	for (i = 0; i < pci_test.offset; ++i) {
		char c = ioreadb(addr + offsetof(struct pci_test_dev_hdr,
						 name) + i, io);
		if (!c) {
			break;
		}
		printf("%c",c);
	}
	printf(":");
	return true;
}

static bool pci_mem_next(struct test *test)
{
	bool ret;
	ret = pci_next(test, ((unsigned long)pci_test.memaddr), false);
	if (ret) {
		pci_test.mem = pci_test.memaddr + pci_test.offset;
	}
	return ret;
}

static bool pci_io_next(struct test *test)
{
	bool ret;
	ret = pci_next(test, ((unsigned long)pci_test.iobar), true);
	if (ret) {
		pci_test.ioport = pci_test.iobar + pci_test.offset;
	}
	return ret;
}

#define THRESHOLD 100000
static struct test tests[] = {
	{ cpuid_test, "cpuid", .parallel = 1,  },
	{ vmcall, "vmcall", .parallel = 1, .threshold = THRESHOLD },
#ifdef __x86_64__
	{ mov_from_cr8, "mov_from_cr8", .parallel = 1, },
	{ mov_to_cr8, "mov_to_cr8" , .parallel = 1, },
#endif
	{ inl_pmtimer, "inl_from_pmtimer", .parallel = 1, },
	{ inl_nop_qemu, "inl_from_qemu", .parallel = 1 },
	{ inl_nop_kernel, "inl_from_kernel", .parallel = 1 },
	{ outl_elcr_kernel, "outl_to_kernel", .parallel = 1 },
	{ mov_dr, "mov_dr", .parallel = 1 },
	{ ipi, "ipi", is_smp, .parallel = 0,  .threshold = THRESHOLD },
	{ ipi_nowait, "ipi-nowait", is_smp, .parallel = 0, .post_test = ipi_nowait_post_test,
 	.threshold = THRESHOLD},
	{ ipi, "ipi-dest-running", is_smp, .parallel = 0,
	  .post_test = ipi_post_test, .pre_test =  ipi_pre_test, .threshold = THRESHOLD },
	{ ipi_halt, "ipi+halt", is_smp, .parallel = 0, },
	{ ple_round_robin, "ple-round-robin", .parallel = 1 },
	{ wr_tsc_adjust_msr, "wr_tsc_adjust_msr", .parallel = 1 },
	{ rd_tsc_adjust_msr, "rd_tsc_adjust_msr", .parallel = 1 },
	{ NULL, "pci-mem", .parallel = 0, .next = pci_mem_next },
	{ NULL, "pci-io", .parallel = 0, .next = pci_io_next },
};

unsigned iterations;
static atomic_t nr_cpus_done;

static void run_test(void *_func)
{
    int i;
    void (*func)(void) = _func;

    for (i = 0; i < iterations; ++i)
        func();

    atomic_inc(&nr_cpus_done);
}

#define TEST_DELAY 10000

static void delay(int count)
{
	while(count--) asm("");
}

#define ITER 10000
static bool do_test(struct test *test)
{
	unsigned long i, iterations;
	unsigned long sample, cycles;
	unsigned long t1, t2;
	unsigned long long min = 0, max = 0;
	unsigned long tmp_result[ITER];
	unsigned long bad_result[ITER];
	int bad_result_idx = 0;

	if (cpu_count() == 1 && !test->parallel) {
		printf("%s requires smp, skip it..\n", test->name);
		goto out;
	}

	if (test->pre_test)
		test->pre_test();

	iterations = ITER;
	cycles = 0;
	for (i = 0; i < iterations; i++) {
		t1 = start();
		test->func();
		t2 = stop();
		/* Wait some cycles until the dest is completely done for IPI */
		delay(TEST_DELAY);
		sample = t2 - t1;
		if (sample == 0 || sample > test->threshold) {
			/* If something went wrong or we had an
			 * overflow, don't count that sample */
			iterations--;
			i--;

			bad_result[bad_result_idx] = sample;
			bad_result_idx++;
			//debug("cycle count overflow: %d\n", sample);
			continue;
		}
		cycles += sample;
		if (min == 0 || min > sample)
			min = sample;
		if (max < sample)
			max = sample;
		tmp_result[i] = sample;
	}

	if (test->post_test)
		test->post_test();

	for (i = 0; i < bad_result_idx; i++)
		printf("Result %ld cycles is not included\n", bad_result[i]);
	printf("%d out of %d is excluded\n", bad_result_idx, ITER);

	printf("%s:\t avg %lu\t min %llu\t max %llu\n",
		test->name, cycles / iterations, min, max);

out:
	return test->next;
}

/*static bool do_test(struct test *test)
{
	int i;
	unsigned long long t1, t2;
        void (*func)(void);

        iterations = 32;

        if (test->valid && !test->valid()) {
		printf("%s (skipped)\n", test->name);
		return false;
	}

	if (test->next && !test->next(test)) {
		return false;
	}

	func = test->func;
        if (!func) {
		printf("%s (skipped)\n", test->name);
		return false;
	}

	do {
		iterations *= 2;
		t1 = rdtsc();

		if (!test->parallel) {
			for (i = 0; i < iterations; ++i)
				func();
		} else {
			atomic_set(&nr_cpus_done, 0);
			for (i = cpu_count(); i > 0; i--)
				on_cpu_async(i-1, run_test, func);
			while (atomic_read(&nr_cpus_done) < cpu_count())
				;
		}
		t2 = rdtsc();
	} while ((t2 - t1) < GOAL);
	printf("%s %d\n", test->name, (int)((t2 - t1) / iterations));
	return test->next;
}*/

static void enable_nx(void *junk)
{
	if (cpuid(0x80000001).d & (1 << 20))
		wrmsr(MSR_EFER, rdmsr(MSR_EFER) | EFER_NX_MASK);
}

bool test_wanted(struct test *test, char *wanted[], int nwanted)
{
	int i;

	if (!nwanted)
		return true;

	for (i = 0; i < nwanted; ++i)
		if (strcmp(wanted[i], test->name) == 0)
			return true;

	return false;
}

int main(int ac, char **av)
{
	struct fadt_descriptor_rev1 *fadt;
	int i;
	unsigned long membar = 0;
	pcidevaddr_t pcidev;

	smp_init();
	setup_vm();
	nr_cpus = cpu_count();

	for (i = cpu_count(); i > 0; i--)
		on_cpu(i-1, enable_nx, 0);

	fadt = find_acpi_table_addr(FACP_SIGNATURE);
	pm_tmr_blk = fadt->pm_tmr_blk;
	printf("PM timer port is %x\n", pm_tmr_blk);

	pcidev = pci_find_dev(PCI_VENDOR_ID_REDHAT, PCI_DEVICE_ID_REDHAT_TEST);
	if (pcidev != PCIDEVADDR_INVALID) {
		for (i = 0; i < PCI_TESTDEV_NUM_BARS; i++) {
			if (!pci_bar_is_valid(pcidev, i)) {
				continue;
			}
			if (pci_bar_is_memory(pcidev, i)) {
				membar = pci_bar_addr(pcidev, i);
				pci_test.memaddr = ioremap(membar, PAGE_SIZE);
			} else {
				pci_test.iobar = pci_bar_addr(pcidev, i);
			}
		}
		printf("pci-testdev at 0x%x membar %lx iobar %x\n",
		       pcidev, membar, pci_test.iobar);
	}

	for (i = 0; i < ARRAY_SIZE(tests); ++i)
		if (test_wanted(&tests[i], av + 1, ac - 1))
			while (do_test(&tests[i])) {}

	return 0;
}
