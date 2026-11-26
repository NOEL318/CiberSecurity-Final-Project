package mx.udlap.lis4062.securesms;

import android.content.Context;
import android.os.Build;
import android.telephony.SmsManager;

import java.util.ArrayList;

/** Sends a (possibly long) text as one concatenated SMS. Returns the number of segments used. */
public final class SmsSender {

    private SmsSender() { }

    @SuppressWarnings("deprecation")
    public static int send(Context ctx, String phone, String text) {
        SmsManager sms = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
                ? ctx.getSystemService(SmsManager.class)
                : SmsManager.getDefault();
        ArrayList<String> parts = sms.divideMessage(text);
        if (parts.size() == 1) {
            sms.sendTextMessage(phone, null, text, null, null);
        } else {
            sms.sendMultipartTextMessage(phone, null, parts, null, null);
        }
        return parts.size();
    }
}
