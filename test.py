import support

support.print_func("Zara")



var = input("Enter your input: ");
print "Received input is : ", var

if ( var  == 100): print "Value of expression is 100"
elif (var >=50): print  "Value is creater than 50"
else: print "The value is lessthan 50"
print "Good bye!"

for letter in 'Python':    
 print 'Current Letter :', letter
   
fruits = ['banana', 'apple',  'mango']
for fruit in fruits:        # Second Example
 print 'Current fruit :', fruit
 
print "================================"



for num in range(0,10):
 print num, 'is a  number'



 
dict = {'Name': 'Zara', 'Age': 7};
print "dict['Name']: ", dict['Name'];
print max(dict)
print dict.keys()

def printme( str ):
   "This prints a passed string into this function"
   print str;
   return;

printme("I'm first call to user defined function!");

def changeme( mylist ):
   "This changes a passed list into this function"
   mylist.append([1,2,3,4]);
   print "Values inside the function: ", mylist
   return

mylist = [10,20,30];
print mylist
changeme( mylist );
print "Values outside the function: ", mylist


