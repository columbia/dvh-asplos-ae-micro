#ifndef __SMP_H
#define __SMP_H
#include <asm/spinlock.h>

void smp_init(void);

int cpu_count(void);
int smp_id(void);
void on_cpu(int cpu, void (*function)(void *data), void *data);
void on_cpu_async(int cpu, void (*function)(void *data), void *data);
void on_cpu_sync_nowait_receive(int cpu, void (*function)(void *data), void *data);
void on_cpu_completion_wait(int cpu);

#endif
