#!/bin/bash
rm -f result
APPEND=''

L0_QEMU=/srv/vm/qemu/x86_64-softmmu/qemu-system-x86_64
L1_QEMU=/root/vm/qemu/x86_64-softmmu/qemu-system-x86_64

#Check if we are on a bare-metal machine
uname -n | grep -q cloudlab
err=$?

if [[ $err == 0 ]]; then
	MY_QEMU=$L0_QEMU
else
	MY_QEMU=$L1_QEMU
fi

for i in `seq 0 9`;
do
	if [ i != 0 ]; then
		APPEND="-a"
	fi
	QEMU=$MY_QEMU ./x86-run x86/vmexit.flat | tee $APPEND result
done

echo "ipi avg"
grep ipi: result | awk '{ print $3 }'
echo "ipi min"
grep ipi: result | awk '{ print $5 }'

echo "ipi-nowait avg"
grep ipi-nowait: result | awk '{ print $3 }'
echo "ipi-nowait min"
grep ipi-nowait: result | awk '{ print $5 }'
