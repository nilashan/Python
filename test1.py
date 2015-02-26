try:
   fh = open("testfile", "w+")
   print("within try block")
   fh.write("This is my test file for exception handling!!")
except IOError:
   print "Error: can\'t find file or read data"
else:
   print "Written content in the file successfully"
   fh.close()

fo = open("testfile", "r+")
str = fo.read(10);
print "Read String is : ", str
fo.close()
for x in range(1,11):
  print '%2d %3d %4d' % (x, x*x, x*x*x)


