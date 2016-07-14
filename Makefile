
all: offtovma test

offtovma: offtovma.c
	gcc -g -O0 $^ -o $@

test: test.c
	gcc -g -O0 $^ -o $@

clean:
	rm -rf offtovma
	rm -rf test
