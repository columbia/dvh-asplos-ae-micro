#!/bin/bash
rm -f result
APPEND=''

L0_QEMU=/srv/vm/qemu/x86_64-softmmu/qemu-system-x86_64
L1_QEMU=/root/vm/qemu/x86_64-softmmu/qemu-system-x86_64

#Check if we are on a bare-metal machine
uname -n | grep -q cloudlab
err=$?

EXIT_TESTS="vmcall ipi ipi-nowait ipi-dest-running"

if [[ $err == 0 ]]; then
	MY_QEMU=$L0_QEMU
else
	MY_QEMU=$L1_QEMU
fi

#Run this command for timer measure
#./x86-run x86/tscdeadline_wr_latency.flat
for i in `seq 0 9`;
do
	if [ i != 0 ]; then
		APPEND="-a"
	fi
	QEMU=$MY_QEMU ./x86-run x86/vmexit.flat --append "$EXIT_TESTS" | tee $APPEND result
done

LIST=( $EXIT_TESTS )
for i in "${LIST[@]}"
do 
	echo $i "avg"
	grep $i: result | awk '{ print $3 }'

	echo $i "min"
	grep $i: result | awk '{ print $5 }'
done
