__author__ = 'nnamasivayam'
import os
#from os.path import join

cwd = os.getcwd()
print cwd
print os.path.exists('memo.txt') # check whether the file is exists or not
print os.listdir(cwd)

count = 0
for (dirname, dirs, files) in os.walk('.'):
   for filename in files:
       if filename.endswith('.py') :
           count = count + 1
print 'Files:', count

for (dirname, dirs, files) in os.walk('.'):
   for filename in files:
       if filename.endswith('.txt') :
           thefile = os.path.join(dirname,filename)
           print os.path.getsize(thefile), thefile