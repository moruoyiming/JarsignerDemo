import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class tests {

    public static void main(String[] args) throws Exception {
        String data = "这是一条测试字符串！";
        String filepath="/Users/jian/123.zip";
        String despath="/Users/jian/what.zip";

        String keyStorePath = "/Users/jian/jamesKeyStore";//秘钥
        String alias = "james";//别名
        String password = "123456";
        String certificatePath = "/Users/jian/test.cer";//证书

        // 私钥签名——公钥验证签名

        System.err.println("私钥签名——公钥验证签名");

//        // 产生签名     //字符串验证 请用  data.getBytes("utf-8")
        String sign = CertificateUtils.signToBase64(getContent(despath), keyStorePath, alias, password);
        System.out.println("私钥签名:" + sign);

        boolean status = CertificateUtils.verifySign(getContent(despath), sign, certificatePath);
        System.err.println("公钥验签结果:" + status);

        // 公钥加密——私钥解密
        System.out.println("\n公钥加密——私钥解密");
        byte[] encrypt = CertificateUtils.encryptByPublicKey(data.getBytes("utf-8"), certificatePath);
        String encode = Base64Util.encode(encrypt);
        System.out.println("公钥加密：" + encode);
        // 下面是安卓加密后的结果，使用 Cipher.getInstance("RSA/None/PKCS1Padding")
        byte[] decrypt = CertificateUtils.decryptByPrivateKey(Base64Util.decode(encode), keyStorePath, alias, password);
        String outputStr = new String(decrypt);

    }

    /**
     * 获取文件 byte[]
     * @param filePath
     * @return
     * @throws IOException
     */
    public static byte[] getContent(String filePath) throws IOException {
        File file = new File(filePath);
        long fileSize = file.length();
        if (fileSize > Integer.MAX_VALUE) {
            System.out.println("file too big...");
            return null;
        }
        FileInputStream fi = new FileInputStream(file);
        byte[] buffer = new byte[(int) fileSize];
        int offset = 0;
        int numRead = 0;
        while (offset < buffer.length
                && (numRead = fi.read(buffer, offset, buffer.length - offset)) >= 0) {
            offset += numRead;
        }
        // 确保所有数据均被读取
        if (offset != buffer.length) {
            throw new IOException("Could not completely read file "
                    + file.getName());
        }
        fi.close();
        return buffer;
    }

}
