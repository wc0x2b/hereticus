/* The helper that a delay-load thunk calls on its first call, which
 * `delayimp.lib` of MSVC holds. The fixtures do not run, so it only has to
 * link. */
void *__delayLoadHelper2(const void *descriptor, void **slot) {
    (void)descriptor;
    return *slot;
}
