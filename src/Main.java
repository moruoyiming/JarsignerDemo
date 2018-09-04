public class Main {

    public static String despath = "/Users/jian/what.zip";

    public static void main(String[] args) {
        boolean what = VerifyFileUtils.verifyJar(despath);
        System.out.println("verify file succeful ？->" + what);
    }
}
