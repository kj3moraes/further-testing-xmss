#ifndef __STRINGY_H__
#define __STRINGY_H__

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// stringy object
typedef struct String {
    unsigned char *str;
    unsigned int length;
} stringy;

/**
 * @brief Constructs a new string object when passed a string as a parameter
 * 
 * @param arr the string to be made into a string object
 * @return stringy* - pointer to the location of the stringy object in heap
 */
stringy *new_stringy(const unsigned char *arr);

/**
 * @brief Deletes a string object safely and returns whether it was
 * successful or not.
 * 
 * @param s the stringy object
 * @return int - exit code for the operation
 */
int stringy_delete(stringy *s);

/**
 * @brief Prepends a given string to the stringy object.
 * @param s stringy object
 * @param t string
 * @return int - exit code for the operation
 */
int prepend(stringy *s, const char *t);

/**
 * @brief Appends a given string to the stringy object.
 * @param s stringy object
 * @param t string
 * @return int - exit code for the operation
 */
int append(stringy *s, const char *t);

#endif