/* From How to Benchmark Code Execution Times on Intel ® IA-32 and IA-64
 * Instruction Set Architectures
 * https://www.intel.com/content/www/us/en/embedded/training/ia-32-ia-64-benchmark-code-execution-paper.html
 */
typedef unsigned long long ticks;

static __inline__ ticks start (void) {
	return rdtsc();
}

static __inline__ ticks stop (void) {
	return rdtsc();
}

/*
static __inline__ ticks start (void) {
  unsigned cycles_low, cycles_high;
  asm volatile ("CPUID\n\t"
		"RDTSC\n\t"
		"mov %%edx, %0\n\t"
		"mov %%eax, %1\n\t": "=r" (cycles_high), "=r" (cycles_low)::
		"%rax", "%rbx", "%rcx", "%rdx");
  return ((ticks)cycles_high << 32) | cycles_low;
}

static __inline__ ticks stop (void) {
	unsigned cycles_low, cycles_high;
	asm volatile("mov %%cr0, %%rax\n\t"
		     "mov %%rax, %%cr0\n\t"
		     "RDTSC\n\t"
		     "mov %%edx, %0\n\t"
		     "mov %%eax, %1\n\t": "=r" (cycles_high), "=r" (cycles_low)::
		     "%rax", "%rdx");
	return ((ticks)cycles_high << 32) | cycles_low;
}
*/
