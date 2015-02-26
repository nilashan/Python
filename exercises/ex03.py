#With a given integral number n, write a program to generate a dictionary that contains (i, i*i) such that
# is an integral number between 1 and n (both included). and then the program should print the dictionary.
#Suppose the following input is supplied to the program:

print 'please give your no'
n=int(raw_input())
d=dict()
for i in range(0,n):
    d[i]=i*i

print d;

