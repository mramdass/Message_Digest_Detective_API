#!/usr/bin/env python
import sys

count = 0

# Running function
def read(stream):
    global count
    for line in stream:
        count += 1
    print 'Total', count

def main(): read(sys.stdin)

if __name__ == "__main__":
    main()
