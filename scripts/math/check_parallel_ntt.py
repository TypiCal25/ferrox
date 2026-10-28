"""Exact-integer model for ParallelNTT.sol. No cryptographic parameter changes."""
import random
q=8380417
zetas=[pow(1753,int(f'{i:08b}'[::-1],2),q) for i in range(256)]
R26=1<<26; INV26=8380415
R32=1<<32; INV32=4236238847

def fw(a):
    a=a[:]; k=1
    for stage in range(8):
        length=128>>stage; bias=(2 if stage<4 else 3 if stage<7 else 4)*q
        for start in range(0,256,2*length):
            z=zetas[k]*R26%q;k+=1
            for j in range(start,start+length):
                x=a[j+length]*z
                m=((x&(R26-1))*INV26)&(R26-1)
                assert x<1<<51 and (x&(R26-1))*INV26<1<<51
                assert x+m*q<1<<51 and (x+m*q)%R26==0
                v=(x+m*q)>>26;u=a[j]
                assert 0<=v<=bias
                a[j]=u+v;a[j+length]=u+bias-v
                assert max(a[j],a[j+length])<1<<51
    assert max(a)<22*q
    return a

def inv(a):
    a=[x%q for x in a]; k=255
    for stage in range(8):
        length=1<<stage;bias=(1<<stage)*q
        for start in range(0,256,2*length):
            z=(-zetas[k]*R32)%q;k-=1
            for j in range(start,start+length):
                u,v=a[j],a[j+length];x=(u+bias-v)*z
                assert x>=0 and x<1<<64
                m=((x&(R32-1))*INV32)&(R32-1)
                assert (x&(R32-1))*INV32<1<<64
                assert x+m*q<1<<64 and (x+m*q)%R32==0
                a[j]=u+v;a[j+length]=(x+m*q)>>32
    scale=pow(256,-1,q)*R32%q
    for j in range(256):
        x=a[j]*scale;m=((x&(R32-1))*INV32)&(R32-1)
        r=(x+m*q)>>32
        assert 0<=r<2*q
        a[j]=r-q if r>=q else r
    return a

def scalar(a):
    a=a[:];k=1
    for stage in range(8):
        length=128>>stage
        for start in range(0,256,2*length):
            z=zetas[k];k+=1
            for j in range(start,start+length):
                u,v=a[j],a[j+length]*z%q
                a[j]=(u+v)%q;a[j+length]=(u-v)%q
    return a

if __name__=='__main__':
    rng=random.Random(77)
    cases=[[0]*256,[q-1]*256,[q-1 if i&1 else 0 for i in range(256)]]
    cases += [[rng.randrange(q) for _ in range(256)] for _ in range(250)]
    for a in cases:
        f=fw(a)
        assert [x%q for x in f]==scalar(a)
        assert inv(f)==a
    for _ in range(100):
        a=[rng.randrange(q*(1<<30)) for _ in range(256)]
        assert [x%q for x in fw(inv(a))]==[x%q for x in a]
    # Also assert actual SWAR arithmetic, including carries between five 51-bit lanes.
    for _ in range(10000):
        vals=[rng.randrange(18*q) for _ in range(5)]
        z=rng.randrange(q); packed=sum(v<<(51*i) for i,v in enumerate(vals));x=packed*z
        mask=sum((R26-1)<<(51*i) for i in range(5))
        m=((x&mask)*INV26)&mask;out=(x+m*q)>>26
        for i,v in enumerate(vals):
            xx=v*z;mm=((xx&(R26-1))*INV26)&(R26-1)
            assert ((out>>(51*i))&((1<<51)-1))==((xx+mm*q)>>26)
    print('PASS: 253 forward/inverse models, 100 raw-accumulator inverses, 10,000 five-lane REDC cases')
