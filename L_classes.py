import sys, os, time, ansible.module_utils.urls


print sys.argv


class MyClass:
    def __init__(self):
        # type: () -> object
        # type: () -> object
        self.prop1 = 1
        self.prop2 = 2
        
    def start(self):
        print("Staring itself with property {}".format(self.prop1))

mycleas = MyClass()
mycleas.start()

mycleas.prop1 = 2

mycleas.start()

source = ['"C:\\My Documents"', 'C:\\Code']
target_dir = 'E:\\Backup'
print type(source)
target = target_dir + os.sep + time.strftime('%Y-%m-%d-%H%M%S') + '.zip'
print target
zip_command = "zip -qr {0} {1}".format(target, ' '.join(source))
print (zip_command)
