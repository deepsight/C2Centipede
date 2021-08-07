import string

def getname(ip):
    tld = ""
    subdomain = ""
    sampleipnodotsreversed = ip.replace(".","")[::-1]
    tlds = [".com", ".net", ".io", ".org"]

    tenchoices_adj = ["green","electric","new","optimal","grand","fast","organic","bio","effective","official"]
    tenchoices_sub = ["ads","network","business","apparel","offer","necessities","market","hub","net","space"]

    vname = tenchoices_adj[int(sampleipnodotsreversed[0])] + tenchoices_sub[int(sampleipnodotsreversed[0])]

    #print(int(sampleipnodotsreversed[-1]))

    if int(sampleipnodotsreversed[0]) >= 0 and int(sampleipnodotsreversed[0]) <= 3:
        tld = ".com"
    elif int(sampleipnodotsreversed[0]) >= 4 and int(sampleipnodotsreversed[0]) <= 6:
        tld = ".net"
    elif int(sampleipnodotsreversed[0]) >= 7 and int(sampleipnodotsreversed[0]) <= 9:
        tld = ".io"

    if int(sampleipnodotsreversed[-1]) >= 0 and int(sampleipnodotsreversed[-1]) <= 3:
        subdomain = "www."
    elif int(sampleipnodotsreversed[-1]) >= 4 and int(sampleipnodotsreversed[-1]) <= 6:
        subdomain = "mail."
    elif int(sampleipnodotsreversed[-1]) >= 7 and int(sampleipnodotsreversed[-1]) <= 9:
        subdomain = "news."

    return subdomain + vname + tld

if __name__ == "__main__":
    import sys
    print(getname(sys.argv[1]))