from charm.toolbox.PKEnc import PKEnc
from charm.toolbox.ecgroup import G
from fastecdsa import ecdsa
import math

class HIKE(PKEnc):
    
    def __init__(self, groupObj):
        PKEnc.__init__(self)
        global group
        group = groupObj
        self.isbyte = True
        self.pp = self.setup()
     
    def setup(self):
        p = group.order()
        curve = group
        g = group.random(G)
        return {'p':p,
                'curve':curve,
                'PRF': lambda msg,sk: group.init(value=ecdsa.sign(msg.decode('utf-8'), int(sk))[0]),
                'g':g}
    
    def keygen(self):
        sk = group.random();
        k = group.hash(group.random())
        sk = {'sk': sk, 'k':k}
        ek = self.pp
        return (sk,ek)
    
    def encrypt(self, sk, label, m):
        l = self.extractLabel(label)
        M = False
        if (isinstance(m,bytes)):
            M = group.encode(m)
        elif (isinstance(m,int)):
            self.isbyte = False
            M = self.pp['g'] ** m
        else:
            raise Exception('Message should be either strings or numbers')
        r = self.pp['PRF'](label,sk['k'])
        ct = M * ((l['Q'] ** r) ** sk['sk'])
        return {'ct': ct}
    
    def generateLabel(self, sk, l, Q):
        l0 = self.pp['g'] ** sk['sk']
        tau = b"2:" + l
        label = b"".join([group.serialize(l0), group.serialize(Q), tau])
        return label
    
    def extractLabel(self,label):
        aux = label.decode("utf-8").split('2:')
        tau = aux[1]
        body = aux[0].split('1:')
        l0 = group.deserialize(str.encode("1:"+body[1]))
        Q = group.deserialize(str.encode("1:"+body[2]))
        
        return {'l0':l0,
                'Q':Q,
                'tau':tau}
    
    def publicKey(self, sk):
        return self.pp['g'] ** sk['sk']
    
    def tokenGen(self, sk, program):
        f = program['f']
        label = program['labels'][program['f'][0]]

        tok = ((self.pp['g'] ** (self.pp['PRF'](label,sk['k'])-f[0])) ** sk['sk'])
        return tok

    def tokenDec(self, sk, ct, tok):
        difference = tok ** sk['sk']
        T = ct['ct'] / difference
        M = False
        if (self.isbyte):
            M = group.decode(T)
        else:
            M = self.bruteforce(T)
        return M
    
    def eval(self, f, ciphertexts):
        aggregated = self.pp['g'] ** 0
        for idx,coeff in enumerate(f):
            if idx>0:
                aggregated *= (ciphertexts[idx-1]['ct']**f[idx])
            else:
                init = self.pp['g'] ** f[idx]
        ct = init * aggregated
        return {'ct': ct}
    
    def destroyEnc(self,ct):
        r = group.random()
        ct['ct'] = ct['ct'] * (self.pp['g'] ** r)
        return ct

    def bruteforce(self, T):
        a = 0
        Q = self.pp['g'] ** a
        b = math.sqrt(math.sqrt(int(self.pp['p'])))
        while a <= b:
            if Q == T:
                return a
            else:
                a += 1
                Q = Q * self.pp['g']
        return "It is not in the index"
    
    def decrypt(self, sk, program, ct):
        partial_sum = 0
        
        for idx,label in enumerate(program['labels']):
            partial_sum += (self.pp['PRF'](label,sk['k']) * program['f'][idx+1])
        
        label = program['labels'][program['f'][0]]
        paramsLabel = self.extractLabel(label)
        
        difference = (paramsLabel['Q'] ** partial_sum) ** sk['sk']
        T = ct['ct'] / difference
        M = False
        if (self.isbyte):
            M = group.decode(T)
        else:
            M = self.bruteforce(T)
        return M
        

def testStringEncryption():
    from charm.toolbox.eccurve import secp256k1
    from charm.toolbox.ecgroup import ECGroup
    
    groupObj = ECGroup(secp256k1)
    hike = HIKE(groupObj)
    (secret_key, eval_key) = hike.keygen()
    (secret_key_prime, eval_key_prime) = hike.keygen()
    
    msg = b"hello world!1234567891234567"
    label = b"label1"

    print('Public Key...')
    Q = hike.publicKey(secret_key_prime)
    print()
    
    label = hike.generateLabel(secret_key, label, Q)

    cipher_text = hike.encrypt(secret_key, label, msg)
    
    program = {'f': [0,1],
               'labels': [label]}
    decrypted_msg = hike.decrypt(secret_key, program, cipher_text)
    
    print("Decrypted message {}".format(decrypted_msg))
    print()
    
    tok = hike.tokenGen(secret_key, program)
    
    msg = hike.tokenDec(secret_key_prime, cipher_text, tok)
    print("TokenDec message {}".format(msg))
    
    print()
    
    print('Destroying ct....')
    ct = hike.destroyEnc(cipher_text)
    decrypted_msg = hike.decrypt(secret_key, program, ct)
    
    print("Decrypted message {}".format(decrypted_msg))
    print()

def testIntEncryption():
    from charm.toolbox.eccurve import secp256k1
    from charm.toolbox.ecgroup import ECGroup
    
    groupObj = ECGroup(secp256k1)
    hike = HIKE(groupObj)
    (secret_key, eval_key) = hike.keygen()
    (secret_key_prime, eval_key_prime) = hike.keygen()
    msg = 10
    label = b"label1"
    
    print('Public Key...')
    Q = hike.publicKey(secret_key_prime)
    print()
    
    label = hike.generateLabel(secret_key, label, Q)
    cipher_text = hike.encrypt(secret_key, label, msg)
    
    program = {'f': [0,1],
               'labels': [label]}
    decrypted_msg = hike.decrypt(secret_key, program, cipher_text)
    
    print("Decrypted message {}".format(decrypted_msg))
    print()

    print('Eval...')
    msg2 = 10
    label2 = b"label2"
    label2 = hike.generateLabel(secret_key, label2, Q)
    program = {'f': [0, 1, 1],
               'labels': [label,label2]}
    
    cipher_text2 = hike.encrypt(secret_key, label2, msg2)

    cipher_text_eval = hike.eval(program['f'], [cipher_text,cipher_text2])
    decrypted_msg = hike.decrypt(secret_key, program, cipher_text_eval)
    print("Decrypted message eval f(0,1,1) and msg[1,1]: {}".format(decrypted_msg))
    print()
    
    print('Token Gen...')
    tok = hike.tokenGen(secret_key, program)
    print()
    
    print('Token Dec...')
    tokenDec = hike.tokenDec(secret_key_prime, cipher_text, tok)
    print("TokenDec message {}".format(tokenDec))

    print()
    
    print('ct: {}'.format(cipher_text['ct']))
    print('Destroying ct....')
    ct = hike.destroyEnc(cipher_text)
    print('ct: {}'.format(ct['ct']))


if __name__ == "__main__":
    testStringEncryption()
    testIntEncryption()