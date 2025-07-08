"""
A simple module that traces BPF events.
"""
import sys

from bcc import BPF

def main() -> int:
    bpf = BPF(text="")
    bpf.trace_print()
    return 0

if __name__ == '__main__':
    sys.exit(main())