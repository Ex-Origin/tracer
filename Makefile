
all: 
	gcc -g gdbpwn.c -o gdbpwn
	gcc -g test.c -o test
	# gcc -g -DDEBUG test.c -o test