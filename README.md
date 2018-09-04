# JarsignerDemo
jarsigner 加密文件，校验文件，JAR 签名和校验工具

项目处于安全考虑,需要对网络上下载的zip包进行完整性校验，从网上找了很久相关资料，大部分都是 复制粘贴，现在将自己总结的分享出来，希望对那些踩坑的朋友 有所
帮助。

第1步：用 keytool 生成 keystore
打开CMD窗口，键入如下命令生成keystore文件，其中jamesKeyStore 为公钥秘钥数据文件，james 是alias 的 key pair，keypass 的值123456是秘钥指令，
 storepass 的值123456是秘钥库指令   注意生成的文件地址 和 签名的地址 请cd到指定目录下操作
 
keytool -genkey -alias james -keypass 123456 -validity 3650 -keystore jamesKeyStore -storepass 123456
keytool -genkey -alias [名称] -keypass [秘钥指令] -validity [时长] -keystore [公钥秘钥数据文件] -storepass [秘钥库指令]

控制台输出 如下内容，并输入相应信息：
输入如下信息:
您的名字与姓氏是什么?
  [Unknown]:  ckkj
您的组织单位名称是什么?
  [Unknown]:  ckkj
您的组织名称是什么?
  [Unknown]:  ckkj
您所在的城市或区域名称是什么?
  [Unknown]:  ckkj
您所在的省/市/自治区名称是什么?
  [Unknown]:  ckkj
该单位的双字母国家/地区代码是什么?
  [Unknown]:  ckkj
CN=ckkj, OU=ckkj, O=ckkj, L=ckkj, ST=ckkj, C=ckkj是否正确?
  [否]:  y

第2步：用 jarsigner 对 Jar包/文件 进行签名
使用如下命令可以在CMD窗口中验证签名JAR包
jarsigner -verbose -keystore [您的私钥存放路径] -signedjar [签名后文件存放路径] [未签名的文件路径] [您的证书名称] 
jarsigner -verbose -keystore jamesKeyStore -signedjar what.zip 123.zip james

输出如下信息:
  输入密钥库的密码短语: 
  正在添加: META-INF/MANIFEST.MF
  正在添加: META-INF/JAMES.SF
  正在添加: META-INF/JAMES.DSA
  …
 jar 已签名。


第3步：用 jarsigner 对 zip包进行认证

jarsigner -verify what.zip
输出如下信息:
jar 已验证。
认证未签名zip包

jarsigner -verify 456.zip

输出如下信息:
没有清单。
jar 未签名。


上边是 通过控制台命令验证 文件签名。下面是代码层的认证：


 /**
     * 验证文件 签名
     *
     * @param filepath 文件路径
     * @return
     * @throws Exception
     */
    public static boolean verifyJar(String filepath) {
        boolean verifySuccesful = true;
        try {    //Insert the full path to the jar here
            JarFile myJar = new JarFile(filepath, true);
            //Don't really need this right now but was using it to inspect the SHA1 hashes
            InputStream is = myJar.getInputStream(myJar.getEntry("META-INF/MANIFEST.MF"));
            is.close();
            Manifest man = myJar.getManifest();
            Enumeration<JarEntry> entries = myJar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                myJar.getInputStream(entry);
                //Also tried actually creating a variable from the stream in case it was discarding it before verification
                //InputStream is = jar.getInputStream(entry);
                //is.close();
            }
        } catch (Exception se) {
            se.printStackTrace();
            verifySuccesful = false;
        }
        return verifySuccesful;
    }


当签名过后文件之后，直接验证，返回true,
当解压文件修改内容之后，从新压缩验证，返回false.


CertificateUtils.class 类是从网上找的Utils.他涉及到一个私钥公钥验证。经过测试。也是可行的。具体内容请看 tests.class 具体内容。





下边 是一些参考资料：
    本项目验证方式参考 这里 ：https://stackoverflow.com/questions/5587656/verifying-jar-signature
    Java中Jar文件及签名工具详解 https://blog.csdn.net/tanga842428/article/details/52425335
    CertificateUtils参考这里 http://www.cnblogs.com/shindo/p/6349070.html
    生成验证参考这里，缺少加密过程，https://www.cnblogs.com/cymiao/p/8398979.html 本文的代码验证方式不可行，不知是我配置有问题还是咋的。
     
 
