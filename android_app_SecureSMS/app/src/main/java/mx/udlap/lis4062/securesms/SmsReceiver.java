package mx.udlap.lis4062.securesms;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.provider.Telephony;
import android.telephony.SmsMessage;
import android.widget.Toast;

import java.util.LinkedHashMap;
import java.util.Map;

import mx.udlap.lis4062.securesms.crypto.CryptoCore;

/**
 * Receiver side of the SMS channel. Android reassembles concatenated (multipart) SMS before this
 * broadcast, so all parts of one encrypted message arrive in the same intent.
 *  - K1:...  -> public key of the sender, stored in the key library under the sender's number
 *  - R1:/E1: -> encrypted message, stored (still encrypted) in the inbox; decrypted on demand
 */
public class SmsReceiver extends BroadcastReceiver {

    @Override
    public void onReceive(Context context, Intent intent) {
        if (!Telephony.Sms.Intents.SMS_RECEIVED_ACTION.equals(intent.getAction())) return;
        SmsMessage[] msgs = Telephony.Sms.Intents.getMessagesFromIntent(intent);
        if (msgs == null) return;

        Map<String, StringBuilder> bySender = new LinkedHashMap<>();
        long when = System.currentTimeMillis();
        for (SmsMessage m : msgs) {
            String from = m.getDisplayOriginatingAddress();
            StringBuilder sb = bySender.get(from);
            if (sb == null) {
                sb = new StringBuilder();
                bySender.put(from, sb);
            }
            sb.append(m.getMessageBody());
            when = m.getTimestampMillis();
        }

        KeyRepository repo = new KeyRepository(context);
        for (Map.Entry<String, StringBuilder> e : bySender.entrySet()) {
            String from = e.getKey();
            String body = e.getValue().toString().trim();
            try {
                if (body.startsWith(CryptoCore.KEY_PREFIX)) {
                    String desc = repo.importKeyShare(from, body);
                    Toast.makeText(context, "Public key received from " + from + ": " + desc,
                            Toast.LENGTH_LONG).show();
                } else if (body.startsWith(CryptoCore.RSA_PREFIX) || body.startsWith(CryptoCore.ECC_PREFIX)) {
                    repo.addToInbox(from, body, when);
                    Toast.makeText(context, "Encrypted SMS received from " + from + " (open Inbox to decrypt)",
                            Toast.LENGTH_LONG).show();
                }
            } catch (Exception ex) {
                Toast.makeText(context, "Invalid secure SMS from " + from + ": " + ex.getMessage(),
                        Toast.LENGTH_LONG).show();
            }
        }
    }
}
