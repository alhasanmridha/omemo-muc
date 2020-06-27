import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jivesoftware.smack.SmackConfiguration;
import org.jivesoftware.smackx.omemo.OmemoConfiguration;
import org.jivesoftware.smackx.omemo.signal.SignalOmemoService;
import org.jxmpp.stringprep.XmppStringprepException;
import websocket.WebSocketConfiguration;
import websocket.XMPPWebSocketConnection;

import java.security.Security;
import java.util.Scanner;


/**
 * Command Line OMEMO Chat Client.
 * This client was developed for testing purposes. It can easily crash for unexpected inputs. Use with that in mind.
 *
 * Created by vanitas on 28.11.16.
 */
public class Main {
    private static String GJID,GPASSWORD;
    private static final String domainName = "ckotha.com";

    private Main() {
        SmackConfiguration.DEBUG = true;
        OmemoConfiguration.setAddOmemoHintBody(false);
    }

    public void start() throws Exception {
        Scanner scanner = new Scanner(System.in);
        String jidname, password;
        jidname = GJID;
        password = GPASSWORD;
        while(jidname == null) {
            System.out.println("Enter username:");
            jidname = scanner.nextLine();
        }
        while (password == null) {
            System.out.println("Enter password:");
            password = scanner.nextLine();
        }
        XMPPWebSocketConnection connection;
        WebSocketConfiguration conf = null;
        try {
            conf = WebSocketConfiguration.builder()
                    .setUseHttps(false)
                    .setHost("157.230.36.183")
                    .setPort(5280)
                    .setFile("xmpp")
                    .setXmppDomain(domainName)
                    .setUsernameAndPassword(GJID, GPASSWORD)
                    .build();
        } catch (XmppStringprepException e) {
            e.printStackTrace();
        }
        connection = new XMPPWebSocketConnection(conf);
        connection.connect();
    }

    public static void main(String[] args) {
        try {
            GJID = args[0];
            GPASSWORD = args[1];
            System.out.println("User: " + GJID);
            Main main = new Main();
            main.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
