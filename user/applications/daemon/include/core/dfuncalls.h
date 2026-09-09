#ifndef _DFUNCALLS_H_
#define _DFUNCALLS_H_

typedef int (*dcomp_init_f)(void);
typedef void (*dcomp_exit_f)(void);

#define DCOMP_INIT_HIGHPRIO(fn) \
    static dcomp_init_f __highprio_init_##fn \
    __attribute__((section("highprio_initfuncs"), used)) = fn

#define DCOMP_EXIT_HIGHPRIO(fn) \
    static dcomp_exit_f __highprio_exit_##fn \
    __attribute__((section("highprio_exitfuncs"), used)) = fn

#define DCOMP_INIT_NORMPRIO(fn) \
    static dcomp_init_f __normprio_init_##fn \
    __attribute__((section("normprio_initfuncs"), used)) = fn

#define DCOMP_EXIT_NORMPRIO(fn) \
    static dcomp_exit_f __normprio_exit_##fn \
    __attribute__((section("normprio_exitfuncs"), used)) = fn

#define DCOMP_INIT_LOWPRIO(fn) \
    static dcomp_init_f __lowprio_init_##fn \
    __attribute__((section("lowprio_initfuncs"), used)) = fn

#define DCOMP_EXIT_LOWPRIO(fn) \
    static dcomp_exit_f __lowprio_exit_##fn \
    __attribute__((section("lowprio_exitfuncs"), used)) = fn

#endif