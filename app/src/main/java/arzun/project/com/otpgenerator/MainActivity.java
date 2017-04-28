package arzun.project.com.otpgenerator;

import android.app.Activity;
import android.os.CountDownTimer;
import android.os.Looper;
import android.os.Message;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import java.lang.reflect.UndeclaredThrowableException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Timestamp;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Random;
import java.util.TimeZone;
import java.util.Timer;
import java.util.TimerTask;
import java.util.logging.Handler;
import java.util.logging.LogRecord;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends AppCompatActivity {

    TextView display;
    Button btnGenerator;
    String otp;
    static String abc;

    // Seed for HMAC-SHA1 - 20 bytes
    String seed = "3132333435363738393031323334353637383930";

    // Seed for HMAC-SHA256 - 32 bytes
    String seed32 = "3132333435363738393031323334353637383930" +
            "313233343536373839303132";

    // Seed for HMAC-SHA512 - 64 bytes
    String seed64 = "3132333435363738393031323334353637383930" +
            "3132333435363738393031323334353637383930" +
            "3132333435363738393031323334353637383930" +
            "31323334";


    String steps = "1";
    long T0 = 0;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);


        display = (TextView) findViewById(R.id.OTP_LOGIN_MSG);
        btnGenerator = (Button) findViewById(R.id.generator);

        final android.os.Handler handler = new android.os.Handler();
        final int time1 = 30000;

        handler.postDelayed(new Runnable() {
            @Override
            public void run() {
                handler.postDelayed(this, time1);
                long X = 30;
                long testTime[] = {59L, 1111111109L, 1111111111L,
                        1234567890L, 2000000000L, 20000000000L};
                DateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                df.setTimeZone(TimeZone.getTimeZone("UTC"));
                try {
                    SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmss");
                    String currentDateandTime = sdf.format(new Date());
                    display.setText(generateTOTP256(seed64, currentDateandTime, "6"));

//                  for (int i = 0; i < testTime.length; i++) {
//                       long T = (testTime[i] - T0) / X;
//                       steps = Long.toHexString(T).toUpperCase();
//                       while (steps.length() < 16) steps = "0" + steps;
//                       String fmtTime = String.format("%1$-11s", testTime[i]);
//                       String utcTime = df.format(new Date(testTime[i] * 1000));
//
//                   }
                } catch (final Exception e) {
                    System.out.println("Error : " + e);
                }
            }
        }, time1);
    }

    public static byte[] hmac_sha(String crypto, byte[] keyBytes, byte[] text) {
        try {
            Mac hmac;
            hmac = Mac.getInstance(crypto);
            SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");
            hmac.init(macKey);
            return hmac.doFinal(text);
        } catch (GeneralSecurityException gse) {
            throw new UndeclaredThrowableException(gse);
        }

    }

    private static byte[] hexStr2Bytes(String hex) {
        // Adding one byte to get the right conversion
        // Values starting with "0" can be converted
        byte[] bArray = new BigInteger("10" + hex, 16).toByteArray();

        // Copy all the REAL bytes, not the "first"
        byte[] ret = new byte[bArray.length - 1];
        for (int i = 0; i < ret.length; i++)
            ret[i] = bArray[i + 1];
        return ret;
    }

    private static final int[] DIGITS_POWER
            // 0 1  2   3    4     5      6       7        8
            = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};

    public static String generateTOTP(String key,
                                      String time,
                                      String returnDigits) {
        return generateTOTP(key, time, returnDigits, "HmacSHA1");
    }

    public static String generateTOTP256(String key,
                                         String time,
                                         String returnDigits) {
        return generateTOTP(key, time, returnDigits, "HmacSHA256");
    }

    public static String generateTOTP512(String key,
                                         String time,
                                         String returnDigits) {
        return generateTOTP(key, time, returnDigits, "HmacSHA512");
    }

//    public char[] sendOTP(int lenght) {
//        String number = "0123456789";
//        Random r = new Random();
//        char[] otp = new char[lenght];
//        for (int i = 0; i < lenght; i++) {
//            otp[i] = number.charAt(r.nextInt(number.length()));
//        }
//        return otp;
//    }

    public static String generateTOTP(String key,
                                      String time,
                                      String returnDigits,
                                      String crypto) {
        int codeDigits = Integer.decode(returnDigits).intValue();
        String result = null;

        // Using the counter
        // First 8 bytes are for the movingFactor
        // Compliant with base RFC 4226 (HOTP)
        while (time.length() < 16)
            time = "0" + time;

        // Get the HEX in a Byte[]
        byte[] msg = hexStr2Bytes(time);
        byte[] k = hexStr2Bytes(key);
        byte[] hash = hmac_sha(crypto, k, msg);

        // put selected bytes into result int
        int offset = hash[hash.length - 1] & 0xf;

        int binary =
                ((hash[offset] & 0x7f) << 24) |
                        ((hash[offset + 1] & 0xff) << 16) |
                        ((hash[offset + 2] & 0xff) << 8) |
                        (hash[offset + 3] & 0xff);

        int otp = binary % DIGITS_POWER[codeDigits];

        result = Integer.toString(otp);
        while (result.length() < codeDigits) {
            result = "0" + result;
        }
        abc=result;
        return result;
    }
}

