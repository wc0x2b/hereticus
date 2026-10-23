/* A small command shell, as firmware holds one, for the tests that find
 * the base of a raw image. Linked statically, it carries the C library too,
 * with its tables of handlers and its messages. */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct command {
    const char *name;
    const char *help;
    int (*run)(int argc, char **argv);
};

static int count_lines(int argc, char **argv) {
    int lines = 0;
    for (int at = 1; at < argc; at++) {
        FILE *file = fopen(argv[at], "r");
        if (file == NULL) {
            fprintf(stderr, "cannot open %s: %s\n", argv[at], strerror(errno));
            return 1;
        }
        for (int character; (character = fgetc(file)) != EOF;) {
            lines += character == '\n';
        }
        fclose(file);
    }
    printf("%d lines\n", lines);
    return 0;
}

static int compare_numbers(const void *left, const void *right) {
    long a = *(const long *)left;
    long b = *(const long *)right;
    return (a > b) - (a < b);
}

static int sort_numbers(int argc, char **argv) {
    long *numbers = calloc((size_t)argc, sizeof *numbers);
    if (numbers == NULL) {
        perror("calloc");
        return 1;
    }
    for (int at = 1; at < argc; at++) {
        numbers[at - 1] = strtol(argv[at], NULL, 0);
    }
    qsort(numbers, (size_t)(argc - 1), sizeof *numbers, compare_numbers);
    for (int at = 0; at < argc - 1; at++) {
        printf("%ld\n", numbers[at]);
    }
    free(numbers);
    return 0;
}

static int show_environment(int argc, char **argv) {
    for (int at = 1; at < argc; at++) {
        const char *value = getenv(argv[at]);
        printf("%s=%s\n", argv[at], value != NULL ? value : "(not set)");
    }
    return 0;
}

static int echo_words(int argc, char **argv) {
    for (int at = 1; at < argc; at++) {
        printf(at + 1 < argc ? "%s " : "%s\n", argv[at]);
    }
    return 0;
}

static const struct command commands[] = {
    {"lines", "count the lines of each file", count_lines},
    {"sort", "sort the numbers given", sort_numbers},
    {"env", "show the environment variables named", show_environment},
    {"echo", "print the words given", echo_words},
};

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s COMMAND [ARGUMENT]...\n", argv[0]);
        for (size_t at = 0; at < sizeof commands / sizeof commands[0]; at++) {
            fprintf(stderr, "  %-8s %s\n", commands[at].name, commands[at].help);
        }
        return 2;
    }
    for (size_t at = 0; at < sizeof commands / sizeof commands[0]; at++) {
        if (strcmp(argv[1], commands[at].name) == 0) {
            return commands[at].run(argc - 1, argv + 1);
        }
    }
    fprintf(stderr, "unknown command: %s\n", argv[1]);
    return 2;
}
