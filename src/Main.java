public class Main {

    public static String despath = "/Users/jian/pr1.jar";

    public static void main(String[] args) {
        boolean what = VerifyFileUtils.verifyJar(despath);
        System.out.println("verify file succeful ？->" + what);
    }
}
