#Write a program which accepts a sequence of comma-separated numbers from console and generate a list and a tuple which contains every number.
#Suppose the following input is supplied to the program:

print 'please enter your no'

values=raw_input()

l=values.split(',')
t=tuple(l)
di=dict(l)
print(l)
print(t)
print(di)