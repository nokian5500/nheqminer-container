package ua.pb.ceb.ipay2.utils;

import java.security.MessageDigest;

/**
 * Created by ivan-nagornyi on 8/14/15.
 */

public class Utils {
    private static final char [] HEX_CHARS = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    private Utils() {
    }

    public static boolean isNullOrEmpty (String string) {
        return string == null || string.trim ().length () == 0;
    }

    public static byte [] SHA1 (String param, String encode) {
        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance ("SHA-1");
            messageDigest.reset ();
            messageDigest.update (param.getBytes (encode));
        } catch (Exception exception) {
            exception.printStackTrace ();
        }
        if (messageDigest != null){
            return messageDigest.digest ();
        }else{
            return null;
        }
    }

    public static String bytesToHex (byte [] raw) {
        int length = raw.length;
        char[] hex = new char [length * 2];
        for (int i = 0; i < length; i++) {
            int value = (raw [i] + 256) % 256;
            int highIndex = value >> 4;
            int lowIndex = value & 0x0f;
            hex [(i * 2)] = HEX_CHARS [highIndex];
            hex [i * 2 + 1] = HEX_CHARS [lowIndex];
        }
        return new String (hex);
    }

}
