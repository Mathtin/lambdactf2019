import random, re, sys
from pycipher import SimpleSubstitution as SimpleSub
from ngram_score import ngram_score

if len(sys.argv) < 2:
    print "Usage: %s file"
    sys.exit()

fitness = ngram_score('english_quadgrams.txt') # load our quadgram statistics

with open(sys.argv[1], 'rb') as f:
    ctext_or = f.read()

ctext = re.sub('[^A-Z]','',ctext_or.upper())
ctext_or = bytearray(ctext_or)

map = {}
for i in range(256):
    map[i] = i

maxkey = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
maxscore = -99e9
parentscore,parentkey = maxscore,maxkey[:]

print "Substitution Cipher solver, you may have to wait several iterations"

i = 0
while True:
    i = i + 1
    random.shuffle(parentkey)
    deciphered = SimpleSub(parentkey).decipher(ctext)
    parentscore = fitness.score(deciphered)
    count = 0
    while count < 1000:
        a = random.randint(0,25)
        b = random.randint(0,25)
        child = parentkey[:]
        # swap two characters in the child
        child[a],child[b] = child[b],child[a]
        deciphered = SimpleSub(child).decipher(ctext)
        score = fitness.score(deciphered)
        # if the child was better, replace the parent with it
        if score > parentscore:
            parentscore = score
            parentkey = child[:]
            count = 0
        count = count+1
    # keep track of best score seen so far
    if parentscore > maxscore:
        maxscore,maxkey = parentscore,parentkey[:]
        print '\nbest score so far:',maxscore,'on iteration',i
        ss = SimpleSub(maxkey)
        print '    best key: '+''.join(maxkey)
        for i in range(26):
            map[ord(maxkey[i].lower())] = ord('a') + i
            map[ord(maxkey[i].upper())] = ord('A') + i
        result = bytearray([map[c] for c in ctext_or])
        print bytes(result)
        break
        
        


