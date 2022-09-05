default: writer_compile
	gcc -Wall -Werror writer.o -o writer_test
	
writer_compile: clean
	gcc -c writer.c
	
clean:
	rm -f writer.o writer_test
	
CROSS_COMPILE: make_cross_compile
	aarch64-none-linux-gnu-gcc -Wall -Werror writer.o -o writer_test -L/home/pranav/install-lnx/gcc-arm-10.2-2020.11-x86_64-aarch64-none-linux-gnu/bin
	
make_cross_compile: clean
	aarch64-none-linux-gnu-gcc -c writer.c 
	


	
