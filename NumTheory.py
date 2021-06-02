# Code to carry out Number Theory functions

# Author: fokumdt
# Last modified: 2020-11-12
# Version: 0.0.1
#!/usr/bin/python3

import math

class NumTheory:
    @staticmethod
    def expMod(b,n,m):
        """Computes the modular exponent of a number"""
        """returns (b^n mod m)"""
        if n==0:
            return 1
        elif n%2==0:
            return NumTheory.expMod((b*b)%m, n/2, m)
        else:
            return(b*NumTheory.expMod(b,n-1,m))%m
    
    @staticmethod
    def gcd_iter(u, v):
        """Iterative Euclidean algorithm to find the greatest common divisor of
           integers u and v"""
        while v:
            u, v = v, u % v
        return abs(u)
    
    @staticmethod
    def lcm(u, v):
        """Returns the lowest common multiple of two integers, u and v"""
        return int((u*v)/NumTheory.gcd_iter(u, v))
    
    @staticmethod
    def ext_Euclid(m,n):
        """Extended Euclidean algorithm. It returns the multiplicative
            inverse of n mod m"""
        a = (1,0,m)
        b = (0,1,n)
        while True:
            if b[2] == 0: return a[2]
            if b[2] == 1: return int(b[1] + (m if b[1] < 0 else 0))
            q = math.floor(a[2]/float(b[2]))
            t = (a[0] - (q * b[0]), a[1] - (q*b[1]), a[2] - (q*b[2]))
            a = b
            b = t
