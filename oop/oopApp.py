from ex2 import Employee
from ex1 import Parent
from ex1 import Child
from ex3 import ComClass
from Sort import myclassforsort


x=Employee("Nilash","200000")
x1=Employee("ewerg","5543654")
x2=Employee("hjk","587487")
x3=Employee("uyu","36265")
x.displayCount();
l=[x,x1,x2,x3]
for i in l:
 i.displayEmployee()



c = Child()          # instance of child
c.childMethod()      # child calls its method
c.parentMethod()     # calls parent's method
c.setAttr(200)       # again call parent's method
c.getAttr()
d=Parent()
e=ComClass()
e.mymethod("Nilashan","26")


print("Enter How many numbers do you want to add")
z=raw_input("n=")
n=int(z)

Arr=list()
print"Enter numbers",
for i in range(0,n):
    Arr.append(raw_input("n= "))

xx=myclassforsort(Arr)

print("Sorted array" ,xx.dosort())


