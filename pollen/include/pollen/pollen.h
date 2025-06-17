#ifndef POLLEN_H
#define POLLEN_H

#define POLLEN_TRACE_TAG "pollen" /* common tag for bpf_printk */

#ifndef SEC /* if current environment does not has SEC yet */
#define SEC(NAME) __attribute__((section(NAME), used)) /* define our own SEC macro */
#endif

#endif //POLLEN_H
