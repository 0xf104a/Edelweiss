/**
 * Architecture-specific structures
 **/
#ifndef __POLLEN_ARCH_H
#define __POLLEN_ARCH_H

/**
 * AOSP due to Soong provides slightly different target architecture
 * So next directive is to fix this
 **/
#ifdef __TARGET_ARCH_x86_64
#define __TARGET_ARCH_x86
#endif

#if defined(__TARGET_ARCH_x86)
struct pt_regs {
  unsigned long r15;
  unsigned long r14;
  unsigned long r13;
  unsigned long r12;
  unsigned long rbp;
  unsigned long rbx;
  unsigned long r11;
  unsigned long r10;
  unsigned long r9;
  unsigned long r8;
  unsigned long rax;
  unsigned long rcx;
  unsigned long rdx;
  unsigned long rsi;
  unsigned long rdi;
  unsigned long orig_rax;
  unsigned long rip;
  unsigned long cs;
  unsigned long eflags;
  unsigned long rsp;
  unsigned long ss;
};
#else
#error Target architecture either is not setted up or not supported
#endif

#endif
