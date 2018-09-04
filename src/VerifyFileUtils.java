import java.io.InputStream;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

/**
 * 验证文件 签名
 */
public class VerifyFileUtils {


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
}
