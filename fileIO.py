import  os
import threading
import shutil
import time

f=open('testfile','w')
position = f.tell();
print("===position> ",position)
print(os.getcwd())
print(f)
f.write("hihihi\n")
f.write('lllllll\n')
f.write('ooooo')
f.close()

s=open('testfile','r+')
str1=s.readline()
str = s.read()

print("==",str1)
print(str)
s.close()

os.rename('testfile', 'testfile1')
print("====Renamed=========")

os.remove('testfile1')
print("====Removed=========")
cwdir=os.getcwd().split()
print('===cwd ===',cwdir)
if (os.path.isdir("/dirname")):
    print('The directory exists')
else:
    print('there is no such directories')
    os.mkdir('dirname')

time.sleep(1)
os.rmdir('dirname')


var='Dir'
os.mkdir(var)
for i in range(0,10):
    var=var+'/sub'
    print(var)
    os.mkdir(var)
    x=var+'/testfile'
    print(x)
    f=open(x,'w')
    f.write("hihihi\n")
    f.close()

    with open(x,'w') as f:
        f.write("hello")




