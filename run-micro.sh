#!/bin/bash
rm -f result
APPEND=''
for i in `seq 0 9`;
do
	if [ i != 0 ]; then
		APPEND="-a"
	fi
	./x86-run x86/vmexit.flat | tee $APPEND result
done
echo "ipi avg"
grep ipi: result | awk '{ print $3 }'
echo "ipi min"
grep ipi: result | awk '{ print $5 }'
