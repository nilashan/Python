class A:
    def first(self, f=None):
        if f is not None:
            print 'first method', f
        else:
            print 'first method'

class B:
    def first(self, f):
        print 'first method'
        f(2,3)
        #self.first = self._first


    def _first(self, f,l):                   # '_' is convention for private name
        print 'first met',f,l

class Employee:
 pass


john = Employee() # Create an empty employee record
# Fill the fields of the record
john.name = 'John Doe'
john.dept = 'computer lab'
john.salary = 1000


print(john.name)

a = A()
a.first()
a.first('something')

b = B()
b.first(b._first)
b.first(3,9)



