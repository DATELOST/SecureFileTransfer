public class RSA {
    public long getD() { return d; }
    public long getE() { return e; }
    public long getN() { return n; }
    private long d;
    private long e;
    private long n;
    private long phi;
    RSA(long e,long n,long phi){ this.e=e; this.n=n;}
    RSA(long p,long q){
        n=p*q;
        phi=(p-1)*(q-1);
        e=getE(phi);
        d=getD(e,phi);
    }
    //欧几里得算法
    private long gcd(long a,long b){ return b==0?a:gcd(b,a%b); }
    private long getE(long n){
        for(long i=2;i<n;++i)if(gcd(n,i)==1) return i;
        return n-1;
    }
    //扩展欧几里得算法求逆元
    private long[] exGcd(long a, long b){
        long[] res = {1,0,a};
        if(b==0) return res;
        else{
            res = exGcd(b,a%b);
            long tmp = res[0];
            res[0] = res[1];
            res[1] = tmp-a/b*res[1];
        }
        return res;
    }
    private long getD(long a,long n){
        long[] res=exGcd(a,n);
        return res[2]==1?(res[0]+n)%n:-1;
    }
    //快速幂
    private long qpow(long a,long b,long c){
        a%=c;
        long res=1;
        while (b>0){
            if(b%2==1)res=res*a%c;
            a=a*a%c;
            b>>=1;
        }
        return res;
    }
    //签字
    long[] sign(String m){
        long[] res = new long[m.length()];
        for(int i=0;i<m.length();++i) res[i]=qpow(m.charAt(i),d,n);
        return res;
    }
    //验证
    boolean verity(long[] s,String m){
        String res="";
        for(int i=0;i<s.length;++i) res+=(char)qpow(s[i],e,n);
        return m.equals(res);
    }
}
