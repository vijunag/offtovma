
all: eod test

eod: offtovma.c
	gcc -g -O0 $^ -o $@

test: test.c
	gcc -g -O0 $^ -o $@

clean:
	rm -rf eod
	rm -rf test
