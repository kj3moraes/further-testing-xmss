#include "stringy.h"

stringy *new_stringy(const unsigned char *arr) {
    stringy *ret = (stringy *)malloc(sizeof(stringy));
    ret->length = strlen(arr);
    ret->str = (unsigned char *)malloc(ret->length * sizeof(unsigned char));
    memcpy(ret->str, arr, ret->length);

    return ret;
}

int stringy_delete(stringy *s) {
    free(s->str);
    return 0;
}

int prepend(stringy *s, const char *t) {
    size_t len = strlen(t);
    memmove(s->str + len, s, s->length + 1);
    memcpy(s->str, t, len);
}

int append(stringy *s, const char *t);