public class Main {
    public static void main(String[] args) throws Exception {
        SecureFileTransfer sender = new SecureFileTransfer("abcdefgh",197,199,0);
        StringBuffer cipherText=sender.send("HelloWorld");
        SecureFileTransfer receiver = new SecureFileTransfer("abcdefgh",
                sender.getRsa().getE(),sender.getRsa().getN(),1);
        System.out.println("接收方---验证数字签名结果: "+receiver.receive(cipherText));
    }
}
