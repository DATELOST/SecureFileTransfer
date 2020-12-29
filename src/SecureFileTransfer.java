public class SecureFileTransfer {
    private String pDesKey; //DES密钥
    public RSA getRsa() { return rsa; }
    private RSA rsa;
    //mode = 0      发送方 此时p/q 用于生成RSA密钥/公钥
    //mode = else   接收方 此时p/q 为协商好的RSA公钥{e,n}
    SecureFileTransfer(String pDesKey,long p,long q,int mode){
        this.pDesKey = pDesKey;
        //通信前生成RSA密钥和公钥或传递协商好的公钥
        if(mode==0)this.rsa = new RSA(p,q);
        else this.rsa = new RSA(p,q,0);
    }
    //发送消息 返回密文
    StringBuffer send(String str) throws Exception {
        while(str.length()%8!=0)str+="0";
        //计算消息摘要
        MD5 md5 = new MD5();
        String h= md5.run(str);
        System.out.println("发送方---明文: "+str);
        System.out.println("发送方---DES密钥: "+pDesKey);
        System.out.println("发送方---RSA密钥: "+String.format("(%d,%d)",rsa.getD(),rsa.getN()));
        System.out.println("发送方---MD5摘要: "+h);
        //数字签名
        long[] digit=rsa.sign(h);
        System.out.print("发送方---RSA数字签名:");
        for(int i=0;i<digit.length;++i){
            System.out.print(" "+digit[i]);
            if(i==digit.length/2)System.out.println();
        }System.out.println();
        //链接消息与数字签名
        for(int i=0;i<digit.length;++i)str+=String.format("%08d", digit[i]);
        //DES加密
        StringBuffer mw = new StringBuffer(str);
        StringBuffer key= new StringBuffer(pDesKey);
        DES des = new DES(mw, key, 0);
        des.run();
        System.out.println("发送方---DES密文: "+des.getcipherText());
        String cipherTextHex = des.getcipherTextHex().toString();
        System.out.println("发送方---DES密文(16进制): "+cipherTextHex.substring(0,cipherTextHex.length()/2)
                +"\n"+cipherTextHex.substring(cipherTextHex.length()/2+1)+"\n");
        return des.getcipherText();
    }
    //接受消息  返回数字签名验证结果
    Boolean receive(StringBuffer mw) throws Exception {
        //DES解密
        StringBuffer key= new StringBuffer(pDesKey);
        DES des = new DES(mw,key,1);
        des.run();
        //分离数字签名和消息
        String str=des.getplainText().toString();
        String m=str.substring(0,str.length()-256);
        str=str.substring(str.length()-256);
        //计算消息摘要
        MD5 md5 = new MD5();
        String h= md5.run(m);
        //验证数字签名
        long[] digit = new long[32];
        for(int i=0;i<32;++i)digit[i]=Long.valueOf(str.substring(i*8,i*8+8));
        System.out.println("接收方---DES明文: "+m);
        System.out.println("接收方---DES密钥: "+pDesKey);
        System.out.println("接收方---RSA公钥: "+String.format("(%d,%d)",rsa.getE(),rsa.getN()));
        System.out.println("接收方---MD5摘要: "+h);
        System.out.print("接收方---RSA数字签名:");
        for(int i=0;i<digit.length;++i){
            System.out.print(" "+digit[i]);
            if(i==digit.length/2)System.out.println();
        }System.out.println();
        return rsa.verity(digit,h);
    }
}
