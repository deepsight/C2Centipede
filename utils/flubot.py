import datetime
import javarandom
import argparse

"""https://securityblog.switch.ch/2021/06/19/android-flubot-enters-switzerland/"""

def get_seed(init, year, month):

    import time
    import math
    from datetime import datetime

    year = year
    month = month - 1
    j = ((year ^ month) ^ 0)
    j2 = j * 2
    j3 = j2 * (year ^ j2)
    j4 = j3 * (month ^ j3)
    # original java code uses long values which is limited to 64 bit
    j5 = (j4 * j4)%2**64
    seed = j5 + init;
    return seed


def get_flubot_domain(seed,max,port):
    # parse arguments
    seedinit = seed

    now = datetime.datetime.utcnow()
    year = now.year
    month = now.month

    # generate domains
    domain = ""
    max_hosts = max
    seed = get_seed(seedinit, year, month)
    # class Random source, https://github.com/MostAwesomeDude/java-random/blob/master/javarandom.py
    r = javarandom.Random(seed)
    domains = []
    for i in range(max_hosts):
        label = ""
        for y in range(15):
            label = label + chr(r.nextInt(25) + 97);
        if (i % 3 == 0):
            domain = label + ".ru"
        elif (i % 2 == 0):
            domain = label + ".su"
        else:
            domain = label + ".cn"
        domain += ":" + str(port)
        domains.append(domain)
    return domains

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Do something.")
    parser.add_argument('-s', '--seed', type=int, required=True)
    parser.add_argument('-n', '--numberOfDomains', type=int, required=True)

    args = parser.parse_args()
    seed = args.seed
    number = args.numberOfDomains
    print(get_flubot_domain(seed,number,0))