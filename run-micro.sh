#!/bin/bash
rm -f result
./x86-run x86/vmexit.flat | tee result
for i in `seq 1 9`;
do
	./x86-run x86/vmexit.flat | tee -a result
done
echo "ipi avg"
grep ipi: result | awk '{ print $3 }'
echo "ipi min"
grep ipi: result | awk '{ print $5 }'
