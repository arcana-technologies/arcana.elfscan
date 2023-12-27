all:
	gcc -c -fPIC golang.c
	gcc -shared -o golang.plugin.so golang.o /opt/elfmaster/lib/libelfmaster.a
clean:
	rm -f golang.plugin.so golang.o
