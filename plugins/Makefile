all:
	gcc -c -fPIC golang.c
	gcc -c -fPIC extended_section.c
	gcc -shared -o golang.plugin.so golang.o /opt/elfmaster/lib/libelfmaster.a
	gcc -shared -o extended_section.plugin.so extended_section.o /opt/elfmaster/lib/libelfmaster.a
clean:
	rm -f golang.plugin.so golang.o
	rm -f extended_section.plugin.so extended_section.o
