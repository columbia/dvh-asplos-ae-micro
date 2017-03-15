#!/bin/bash
./x86-run x86/vmexit.flat | tee result
for i in `seq 1 9`;
do
	./x86-run x86/vmexit.flat | tee -a result
done
echo "vmcall avg"
grep vmcall result | awk '{ print $3 }'
echo "vmcall min"
grep vmcall result | awk '{ print $5 }'
echo "outl_to_kernel avg"
grep outl_to_kernel result | awk '{ print $3 }'
echo "outl_to_kernel min"
grep outl_to_kernel result | awk '{ print $5 }'
