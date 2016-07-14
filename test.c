
#include <stdio.h>
#include <malloc.h>

typedef struct Foo {
    int magic;
    int value;
} Foo;

#define INIT_VAL(_p, _v) \
    (_p)->magic = 0xdeadbeef; \
    (_p)->value = _v;

int main()
{
  int *null = NULL;
  int i;

  for(i = 0; i < 30000; ++i) {
      Foo *foo = (Foo*)malloc(sizeof(Foo));
      INIT_VAL(foo, i);
  }
  *null = 1;
}

