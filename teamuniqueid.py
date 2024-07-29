import random
import math

digits = [i for i in range(0, 10)]
def genteamid():

    random_str = ""

    for i in range(6):
        index = math.floor(random.random() * 10)
        random_str += str(digits[index])
    return int(random_str)

def adotp():
    u_c=[chr(i)for i in range(ord('A'),ord('Z')+1)]
    l_c=[chr(i)for i in range(ord('a'),ord('z')+1)]
    adminotp=''
    for i in range(2):
        adminotp+=random.choice(u_c)
        adminotp+=str(random.randint(0,9))
        adminotp+=random.choice(l_c)
    return adminotp
