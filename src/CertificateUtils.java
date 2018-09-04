import javax.crypto.Cipher;
import java.io.*;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * <p>
 * 数字签名/加密解密工具包
 * </p>
 *
 * @author TerryLau
 * @date 2016-12-30
 * @version 1.0
 */
@SuppressWarnings("unused")
public class CertificateUtils {

    /**
     * Java密钥库(Java 密钥库，JKS)KEY_STORE
     */
    public static final String KEY_STORE = "JKS";
    /**
     * 数字证书类型
     */
    public static final String X509 = "X.509";

    /**
     * 文件读取缓冲区大小
     */
    private static final int CACHE_SIZE = 2048;

    /**
     * 最大文件加密块
     */
    private static final int MAX_ENCRYPT_BLOCK = 117;

    /**
     * 最大文件解密块
     */
    private static final int MAX_DECRYPT_BLOCK = 256;

    /****************证书数据加密算法***************/
    private static final String SHA1WithRSA = "SHA1WithRSA";
    private final static String MD5withRSA = "MD5withRSA";
    private static final String SHA224WithRSA = "SHA224WithRSA";
    private static final String SHA256WithRSA = "SHA256WithRSA";
    private static final String SHA384WithRSA = "SHA384WithRSA";
    private static final String SHA512WithRSA = "SHA512WithRSA";
    private static final String RSA = "RSA";
    private static final String ECB = "ECB";
    private static final String PCKCS1PADDING = "PCKCS1Padding";

    /****************证书加密模式***************/

    /**
     * <p>
     * 根据密钥库获得私钥
     * </p>
     *
     * @param keyStorePath 密钥库存储路径
     * @param alias 密钥库别名
     * @param password 密钥库密码
     * @return
     * @throws Exception
     */
    private static PrivateKey getPrivateKey(String keyStorePath, String alias, String password) throws Exception {
        KeyStore keyStore = getKeyStore(keyStorePath, password);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
        return privateKey;
    }

    /**
     * <p>
     * 获得密钥库
     * </p>
     *
     * @param keyStorePath 密钥库存储路径
     * @param password 密钥库密码
     * @return
     * @throws Exception
     */
    private static KeyStore getKeyStore(String keyStorePath, String password) throws Exception {
        FileInputStream in = null;
        try {
            in = new FileInputStream(keyStorePath);
            KeyStore keyStore = KeyStore.getInstance(KEY_STORE);
            keyStore.load(in, password.toCharArray());
            return keyStore;
        } catch (Exception e) {
            System.out.println(e.getMessage());
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    System.out.println(e.getMessage());
                }
            }
        }
        return null;
    }

    /**
     * <p>
     * 根据证书获得公钥
     * </p>
     *
     * @param certificatePath 证书存储路径
     * @return
     * @throws Exception
     */
    private static PublicKey getPublicKey(String certificatePath) throws Exception {
        Certificate certificate = getCertificate(certificatePath);
        PublicKey publicKey = certificate.getPublicKey();
        return publicKey;
    }

    /**
     * <p>
     * 获得证书
     * </p>
     *
     * @param certificatePath 证书存储路径
     * @return
     * @throws Exception
     */
    private static Certificate getCertificate(String certificatePath) throws Exception {
        InputStream in = null;
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance(X509);
            in = new FileInputStream(certificatePath);
            Certificate certificate = certificateFactory.generateCertificate(in);
            return certificate;
        } catch (Exception e) {
            System.out.println(e.getMessage());
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    System.out.println(e.getMessage());
                }
            }
        }
        return null;
    }

    /**
     * <p>
     * 根据密钥库获得证书
     * </p>
     *
     * @param keyStorePath 密钥库存储路径
     * @param alias 密钥库别名
     * @param password 密钥库密码
     * @return
     * @throws Exception
     */
    private static Certificate getCertificate(String keyStorePath, String alias, String password) throws Exception {
        KeyStore keyStore = getKeyStore(keyStorePath, password);
        Certificate certificate = keyStore.getCertificate(alias);
        return certificate;
    }

    /**
     * <p>
     * 私钥加密
     * </p>
     *
     * @param data 源数据
     * @param keyStorePath 密钥库存储路径
     * @param alias 密钥库别名
     * @param password 密钥库密码
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPrivateKey(byte[] data, String keyStorePath, String alias, String password) throws Exception {
        ByteArrayOutputStream out = null;
        try {
            // 取得私钥
            PrivateKey privateKey = getPrivateKey(keyStorePath, alias, password);
            Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            int inputLen = data.length;
            out = new ByteArrayOutputStream();
            int offSet = 0;
            byte[] cache = null;
            int i = 0;
            // 对数据分段加密
            while (inputLen - offSet > 0) {
                if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                    cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
                } else {
                    cache = cipher.doFinal(data, offSet, inputLen - offSet);
                }
                out.write(cache, 0, cache.length);
                i++;
                offSet = i * MAX_ENCRYPT_BLOCK;
            }
            byte[] encryptedData = out.toByteArray();
            return encryptedData;
        } catch (Exception e) {
            System.out.println(e.getMessage());
        } finally {
            if (out != null) {
                try {
                    out.close();
                } catch (IOException e) {
                    System.out.println(e.getMessage());
                }
            }
        }
        return null;
    }

    /**
     * <p>
     * 文件私钥加密
     * </p>
     * <p>
     * 过大的文件可能会导致内存溢出
     * </>
     *
     * @param filePath 文件路径
     * @param keyStorePath 密钥库存储路径
     * @param alias 密钥库别名
     * @param password 密钥库密码
     * @return
     * @throws Exception
     */
    public static byte[] encryptFileByPrivateKey(String filePath, String keyStorePath, String alias, String password) throws Exception {
        byte[] data = fileToByte(filePath);
        return encryptByPrivateKey(data, keyStorePath, alias, password);
    }

    /**
     * <p>
     * 文件加密
     * </p>
     *
     * @param srcFilePath 源文件
     * @param destFilePath 加密后文件
     * @param keyStorePath 密钥库存储路径
     * @param alias 密钥库别名
     * @param password 密钥库密码
     * @throws Exception
     */
    public static void encryptFileByPrivateKey(String srcFilePath, String destFilePath, String keyStorePath, String alias, String password)
            throws Exception {
        FileInputStream in = null;
        OutputStream out = null;
        try {
            // 取得私钥
            PrivateKey privateKey = getPrivateKey(keyStorePath, alias, password);
            Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            File srcFile = new File(srcFilePath);
            in = new FileInputStream(srcFile);
            File destFile = new File(destFilePath);
            if (!destFile.getParentFile().exists()) {
                destFile.getParentFile().mkdirs();
            }
            destFile.createNewFile();
            out = new FileOutputStream(destFile);
            byte[] data = new byte[MAX_ENCRYPT_BLOCK];
            // 创建加密块
            byte[] encryptedData = null;
            while (in.read(data) != -1) {
                encryptedData = cipher.doFinal(data);
                out.write(encryptedData, 0, encryptedData.length);
                out.flush();
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        } finally {
            if (out != null) {
                try {
                    out.close();
                } catch (IOException e) {
                    System.out.println(e.getMessage());
                }
            }
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    System.out.println(e.getMessage());
                }
            }
        }
    }

    /**
     * <p>
     * 文件加密成BASE64编码的字符串
     * </p>
     *
     * @param filePath 文件路径
     * @param keyStorePath 密钥库存储路径
     * @param alias 密钥库别名
     * @param password 密钥库密码
     * @return
     * @throws Exception
     */
    public static String encryptFileToBase64ByPrivateKey(String filePath, String keyStorePath, String alias, String password) throws Exception {
        byte[] encryptedData = encryptFileByPrivateKey(filePath, keyStorePath, alias, password);
        return Base64Util.encode(encryptedData);
    }

    /**
     * <p>
     * 私钥解密
     * </p>
     *
     * @param encryptedData 已加密数据
     * @param keyStorePath 密钥库存储路径
     * @param alias 密钥库别名
     * @param password 密钥库密码
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPrivateKey(byte[] encryptedData, String keyStorePath, String alias, String password) throws Exception {
        ByteArrayOutputStream out = null;
        try {
            // 取得私钥
            PrivateKey privateKey = getPrivateKey(keyStorePath, alias, password);
            Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            int inputLen = encryptedData.length;
            out = new ByteArrayOutputStream();
            int offSet = 0;
            byte[] cache;
            int i = 0;
            // 对数据分段解密
            while (inputLen - offSet > 0) {
                if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                    cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
                } else {
                    cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
                }
                out.write(cache, 0, cache.length);
                i++;
                offSet = i * MAX_DECRYPT_BLOCK;
            }
            byte[] decryptedData = out.toByteArray();
            return decryptedData;
        } catch (Exception e) {
            System.out.println(e.getMessage());
        } finally {
            if (out != null) {
                try {
                    out.close();
                } catch (IOException e) {
                    System.out.println(e.getMessage());
                }
            }
        }
        return null;
    }

    /**
     * <p>
     * 公钥加密
     * </p>
     *
     * @param data 源数据
     * @param certificatePath 证书存储路径
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPublicKey(byte[] data, String certificatePath) throws Exception {
        ByteArrayOutputStream out = null;
        try {
            // 取得公钥
            PublicKey publicKey = getPublicKey(certificatePath);
            Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            int inputLen = data.length;
            out = new ByteArrayOutputStream();
            int offSet = 0;
            byte[] cache;
            int i = 0;
            // 对数据分段加密
            while (inputLen - offSet > 0) {
                if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                    cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
                } else {
                    cache = cipher.doFinal(data, offSet, inputLen - offSet);
                }
                out.write(cache, 0, cache.length);
                i++;
                offSet = i * MAX_ENCRYPT_BLOCK;
            }
            byte[] encryptedData = out.toByteArray();
            return encryptedData;
        } catch (Exception e) {
            System.out.println(e.getMessage());
        } finally {
            if (out != null) {
                try {
                    out.close();
                } catch (IOException e) {
                    System.out.println(e.getMessage());
                }
            }
        }
        return null;
    }

    /**
     * <p>
     * 公钥解密
     * </p>
     *
     * @param encryptedData 已加密数据
     * @param certificatePath 证书存储路径
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPublicKey(byte[] encryptedData, String certificatePath) throws Exception {
        ByteArrayOutputStream out = null;
        try {
            PublicKey publicKey = getPublicKey(certificatePath);
            Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            int inputLen = encryptedData.length;
            out = new ByteArrayOutputStream();
            int offSet = 0;
            byte[] cache;
            int i = 0;
            // 对数据分段解密
            while (inputLen - offSet > 0) {
                if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                    cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
                } else {
                    cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
                }
                out.write(cache, 0, cache.length);
                i++;
                offSet = i * MAX_DECRYPT_BLOCK;
            }
            byte[] decryptedData = out.toByteArray();
            return decryptedData;
        } catch (Exception e) {
            System.out.println(e.getMessage());
        } finally {
            if (out != null) {
                try {
                    out.close();
                } catch (IOException e) {
                    System.out.println(e.getMessage());
                }
            }
        }
        return null;
    }

    /**
     * <p>
     * 文件解密
     * </p>
     *
     * @param srcFilePath 源文件
     * @param destFilePath 目标文件
     * @param certificatePath 证书存储路径
     * @throws Exception
     */
    public static void decryptFileByPublicKey(String srcFilePath, String destFilePath, String certificatePath) throws Exception {
        FileInputStream in = null;
        OutputStream out = null;
        try {
            PublicKey publicKey = getPublicKey(certificatePath);
            Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            File srcFile = new File(srcFilePath);
            in = new FileInputStream(srcFile);
            File destFile = new File(destFilePath);
            if (!destFile.getParentFile().exists()) {
                destFile.getParentFile().mkdirs();
            }
            destFile.createNewFile();
            out = new FileOutputStream(destFile);
            byte[] data = new byte[MAX_DECRYPT_BLOCK];
            byte[] decryptedData; // 解密块
            while (in.read(data) != -1) {
                decryptedData = cipher.doFinal(data);
                out.write(decryptedData, 0, decryptedData.length);
                out.flush();
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        } finally {
            if (out != null) {
                try {
                    out.close();
                } catch (IOException e) {
                    System.out.println(e.getMessage());
                }
            }
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    System.out.println(e.getMessage());
                }
            }
        }
    }

    /**
     * <p>
     * 生成数据签名
     * </p>
     *
     * @param data 源数据
     * @param keyStorePath 密钥库存储路径
     * @param alias 密钥库别名
     * @param password 密钥库密码
     * @return
     * @throws Exception
     */
    public static byte[] sign(byte[] data, String keyStorePath, String alias, String password) throws Exception {
        // 获得证书
//        X509Certificate x509Certificate = (X509Certificate) getCertificate(keyStorePath, alias, password);
        // 获取私钥
        KeyStore keyStore = getKeyStore(keyStorePath, password);
        // 取得私钥
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
        // 构建签名
//        Signature signature = Signature.getInstance(x509Certificate.getSigAlgName());
        Signature signature = Signature.getInstance(SHA1WithRSA);
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    /**
     * <p>
     * 生成数据签名并以BASE64编码
     * </p>
     *
     * @param data 源数据
     * @param keyStorePath 密钥库存储路径
     * @param alias 密钥库别名
     * @param password 密钥库密码
     * @return
     * @throws Exception
     */
    public static String signToBase64(byte[] data, String keyStorePath, String alias, String password) throws Exception {
        return Base64Util.encode(sign(data, keyStorePath, alias, password));
    }

    /**
     * <p>
     * 生成文件数据签名(BASE64)
     * </p>
     * <p>
     * 需要先将文件私钥加密，再根据加密后的数据生成签名(BASE64)，适用于小文件
     * </p>
     *
     * @param filePath 源文件
     * @param keyStorePath 密钥库存储路径
     * @param alias 密钥库别名
     * @param password 密钥库密码
     * @return
     * @throws Exception
     */
    public static String signFileToBase64WithEncrypt(String filePath, String keyStorePath, String alias, String password) throws Exception {
        byte[] encryptedData = encryptFileByPrivateKey(filePath, keyStorePath, alias, password);
        return signToBase64(encryptedData, keyStorePath, alias, password);
    }


    /**
     * <p>
     * 生成文件数字签名
     * </p>
     *
      * <p>
     * <b>注意：</b><br>
     * 生成签名时update的byte数组大小和验证签名时的大小应相同，否则验证无法通过
     * </p>
     *
     * @param filePath
     * @param keyStorePath
     * @param alias
     * @param password
     * @return
     * @throws Exception
     */
    public static byte[] generateFileSign(String filePath, String keyStorePath, String alias, String password) throws Exception {
        FileInputStream in = null;
        try {
            byte[] sign = null;
            // 获得证书
            X509Certificate x509Certificate = (X509Certificate) getCertificate(keyStorePath, alias, password);
            // 获取私钥
            KeyStore keyStore = getKeyStore(keyStorePath, password);
            // 取得私钥
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
            // 构建签名
            Signature signature = Signature.getInstance(x509Certificate.getSigAlgName());
            signature.initSign(privateKey);
            File file = new File(filePath);
            if (file.exists()) {
                in = new FileInputStream(file);
                byte[] cache = new byte[CACHE_SIZE];
                int nRead = 0;
                while ((nRead = in.read(cache)) != -1) {
                    signature.update(cache, 0, nRead);
                }
                sign = signature.sign();
            }
            return sign;
        } catch (Exception e) {
            System.out.println(e.getMessage());
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    System.out.println(e.getMessage());
                }
            }
        }
        return null;
    }

    /**
     * <p>
     * 文件签名成BASE64编码字符串
     * </p>
     *
     * @param filePath
     * @param keyStorePath
     * @param alias
     * @param password
     * @return
     * @throws Exception
     */
    public static String signFileToBase64(String filePath, String keyStorePath, String alias, String password) throws Exception {
        return Base64Util.encode(generateFileSign(filePath, keyStorePath, alias, password));
    }

    /**
     * <p>
     * 验证签名
     * </p>
     *
     * @param data 已加密数据
     * @param sign 数据签名[BASE64]
     * @param certificatePath 证书存储路径
     * @return
     * @throws Exception
     */
    public static boolean verifySign(byte[] data, String sign, String certificatePath) throws Exception {
        // 获得证书
        X509Certificate x509Certificate = (X509Certificate) getCertificate(certificatePath);
        // 获得公钥
        PublicKey publicKey = x509Certificate.getPublicKey();
        // 构建签名
//        Signature signature = Signature.getInstance(x509Certificate.getSigAlgName());
        Signature signature = Signature.getInstance(SHA1WithRSA);
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(Base64Util.decode(sign));
    }

    /**
     * <p>
     * 校验文件签名
     * </p>
     *
     * @param filePath
     * @param sign
     * @param certificatePath
     * @return
     * @throws Exception
     */
    public static boolean validateFileSign(String filePath, String sign, String certificatePath) throws Exception {
        boolean result = false;
        FileInputStream in = null;
        try {
            // 获得证书
            X509Certificate x509Certificate = (X509Certificate) getCertificate(certificatePath);
            // 获得公钥
            PublicKey publicKey = x509Certificate.getPublicKey();
            // 构建签名
            Signature signature = Signature.getInstance(x509Certificate.getSigAlgName());
            signature.initVerify(publicKey);
            File file = new File(filePath);
            if (file.exists()) {
                byte[] decodedSign = Base64Util.decode(sign);
                in = new FileInputStream(file);
                byte[] cache = new byte[CACHE_SIZE];
                int nRead = 0;
                while ((nRead = in.read(cache)) != -1) {
                    signature.update(cache, 0, nRead);
                }
                result = signature.verify(decodedSign);
            }
            return result;
        } catch (Exception e) {
            System.out.println(e.getMessage());
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    System.out.println(e.getMessage());
                }
            }
        }
        return result;
    }

    /**
     * <p>
     * BASE64解码->签名校验
     * </p>
     *
     * @param base64String BASE64编码字符串
     * @param sign 数据签名[BASE64]
     * @param certificatePath 证书存储路径
     * @return
     * @throws Exception
     */
    public static boolean verifyBase64Sign(String base64String, String sign, String certificatePath) throws Exception {
        byte[] data = Base64Util.decode(base64String);
        return verifySign(data, sign, certificatePath);
    }

    /**
     * <p>
     * BASE64解码->公钥解密-签名校验
     * </p>
     *
     *
     * @param base64String BASE64编码字符串
     * @param sign 数据签名[BASE64]
     * @param certificatePath 证书存储路径
     * @return
     * @throws Exception
     */
    public static boolean verifyBase64SignWithDecrypt(String base64String, String sign, String certificatePath) throws Exception {
        byte[] encryptedData = Base64Util.decode(base64String);
        byte[] data = decryptByPublicKey(encryptedData, certificatePath);
        return verifySign(data, sign, certificatePath);
    }

    /**
     * <p>
     * 文件公钥解密->签名校验
     * </p>
     *
     * @param encryptedFilePath 加密文件路径
     * @param sign 数字证书[BASE64]
     * @param certificatePath
     * @return
     * @throws Exception
     */
    public static boolean verifyFileSignWithDecrypt(String encryptedFilePath, String sign, String certificatePath) throws Exception {
        byte[] encryptedData = fileToByte(encryptedFilePath);
        byte[] data = decryptByPublicKey(encryptedData, certificatePath);
        return verifySign(data, sign, certificatePath);
    }

    /**
     * <p>
     * 校验证书当前是否有效
     * </p>
     *
     * @param certificate 证书
     * @return
     */
    public static boolean verifyCertificate(Certificate certificate) {
        return verifyCertificate(new Date(), certificate);
    }

    /**
     * <p>
     * 验证证书是否过期或无效
     * </p>
     *
     * @param date 日期
     * @param certificate 证书
     * @return
     */
    public static boolean verifyCertificate(Date date, Certificate certificate) {
        boolean isValid = true;
        try {
            X509Certificate x509Certificate = (X509Certificate) certificate;
            x509Certificate.checkValidity(date);
        } catch (Exception e) {
            isValid = false;
        }
        return isValid;
    }

    /**
     * <p>
     * 验证数字证书是在给定的日期是否有效
     * </p>
     *
     * @param date 日期
     * @param certificatePath 证书存储路径
     * @return
     */
    public static boolean verifyCertificate(Date date, String certificatePath) {
        Certificate certificate;
        try {
            certificate = getCertificate(certificatePath);
            return verifyCertificate(certificate);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * <p>
     * 验证数字证书是在给定的日期是否有效
     * </p>
     *
     * @param keyStorePath 密钥库存储路径
     * @param alias 密钥库别名
     * @param password 密钥库密码
     * @return
     */
    public static boolean verifyCertificate(Date date, String keyStorePath, String alias, String password) {
        Certificate certificate;
        try {
            certificate = getCertificate(keyStorePath, alias, password);
            return verifyCertificate(certificate);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * <p>
     * 验证数字证书当前是否有效
     * </p>
     *
     * @param keyStorePath 密钥库存储路径
     * @param alias 密钥库别名
     * @param password 密钥库密码
     * @return
     */
    public static boolean verifyCertificate(String keyStorePath, String alias, String password) {
        return verifyCertificate(new Date(), keyStorePath, alias, password);
    }

    /**
     * <p>
     * 验证数字证书当前是否有效
     * </p>
     *
     * @param certificatePath 证书存储路径
     * @return
     */
    public static boolean verifyCertificate(String certificatePath) {
        return verifyCertificate(new Date(), certificatePath);
    }

    /**
     * <p>
     * 文件转换为byte数组
     * </p>
     *
     * @param filePath 文件路径
     * @return
     * @throws Exception
     */
    public static byte[] fileToByte(String filePath) throws Exception {
        byte[] data = null;
        FileInputStream in = null;
        ByteArrayOutputStream out = null;
        try {
            File file = new File(filePath);
            if (file.exists()) {
                in = new FileInputStream(file);
                out = new ByteArrayOutputStream(2048);
                byte[] cache = new byte[CACHE_SIZE];
                int nRead = 0;
                while ((nRead = in.read(cache)) != -1) {
                    out.write(cache, 0, nRead);
                    out.flush();
                }
                data = out.toByteArray();
            }
            return data;
        } catch (Exception e) {
            System.out.println(e.getMessage());
        } finally {
            if (out != null) {
                try {
                    out.close();
                } catch (IOException e) {
                    System.out.println(e.getMessage());
                }
            }
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    System.out.println(e.getMessage());
                }
            }
        }
        return null;
    }

    /**
     * <p>
     * 二进制数据写文件
     * </p>
     *
     * @param bytes 二进制数据
     * @param filePath 文件生成目录
     */
    public static void byteArrayToFile(byte[] bytes, String filePath) throws Exception {
        InputStream in = null;
        OutputStream out = null;
        try {
            in = new ByteArrayInputStream(bytes);
            File destFile = new File(filePath);
            if (!destFile.getParentFile().exists()) {
                destFile.getParentFile().mkdirs();
            }
            destFile.createNewFile();
            out = new FileOutputStream(destFile);
            byte[] cache = new byte[CACHE_SIZE];
            int nRead = 0;
            while ((nRead = in.read(cache)) != -1) {
                out.write(cache, 0, nRead);
                out.flush();
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        } finally {
            if (out != null) {
                try {
                    out.close();
                } catch (IOException e) {
                    System.out.println(e.getMessage());
                }
            }
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    System.out.println(e.getMessage());
                }
            }
        }
    }

    /**
     * <p>
     * 字符串 转 二进制数组
     * </p>
     *
     * @param src 待转换数据
     * @param type 字符类型
     * @return byte[]
     * @throws Exception
     */
    public static byte[] StringToByte(String src, String type) throws Exception {
        try {
            return src.getBytes(type);
        } catch (UnsupportedEncodingException e) {
            System.out.println(e.getMessage());
        }
        return null;
    }

    /**
     * <p>
     * 二进制数组 转 字符串
     * </p>
     *
     * @param src 待转换二进制数组
     * @param type 字符类型
     * @return byte[]
     * @throws Exception
     */
    public static String ByteToString(byte[] src, String type) throws Exception {
        try {
            return new String(src, type);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return null;
    }

    /**
     * <p>
     * 数据URLDecoder解码
     * </p>
     *
     * @param src 待转换数据
     * @param type 编码类型
     * @return String
     * @throws Exception
     */
    public static String decode(String src, String type) throws Exception {
        try {
            return URLDecoder.decode(src, type);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return null;

    }

    /**
     * <p>
     * 数据URLEncoder编码
     * </p>
     *
     * @param src 待转换数据
     * @param type 编码类型
     * @return String
     * @throws Exception
     */
    public static String encode(String src, String type) throws Exception {
        try {
            return URLEncoder.encode(src, type);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return null;

    }
}