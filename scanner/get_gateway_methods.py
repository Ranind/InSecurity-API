#python3

#
#
#       get_gateway Method
#
#

import subprocess

def get_gateway():
    """
    Return the default gateway of the host calling this function
    """
    route = subprocess.Popen(['route', '-n'], stdout=subprocess.PIPE)
    output = subprocess.check_output(['awk', 'FNR == 3 {print $2}'],
            stdin=route.stdout)
    route.wait()
    return output.decode('UTF-8').rstrip()