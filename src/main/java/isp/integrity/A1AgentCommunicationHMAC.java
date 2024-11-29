package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.KeyGenerator;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import javax.crypto.Mac;
import java.security.MessageDigest;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key, provide integrity to the channel
 * using HMAC implemented with SHA256. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A1AgentCommunicationHMAC {
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for hash based message authentication code.
         */
        final Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();
        System.out.println("Key: " + Agent.hex(key.getEncoded()));

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                String[] texts = {
                    "Hello Bob, this is message 1 from Alice.",
                    "I hope you're doing well. Here's message 2.",
                    "The weather is nice today. Message 3.",
                    "Remember our meeting tomorrow. Message 4.",
                    "I'm looking forward to seeing you. Message 5.",
                    "Don't forget to bring the documents. Message 6.",
                    "Let's have lunch next week. Message 7.",
                    "I've finished the project. Message 8.",
                    "Can you review my work? Message 9.",
                    "This is the last message, number 10. Bye!"
                };

                final Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(key);

                for (String text : texts) {
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);
                    final byte[] tag = mac.doFinal(pt);
                    
                    send("bob", pt);
                    send("bob", tag);
                    
                    byte[] response = receive("bob");
                    System.out.println("Alice received: " + new String(response, StandardCharsets.UTF_8));
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(key);

                for (int i = 0; i < 10; i++) {
                    final byte[] pt = receive("alice");
                    final byte[] receivedTag = receive("alice");

                    final byte[] computedTag = mac.doFinal(pt);
                    
                    if (MessageDigest.isEqual(receivedTag, computedTag)) {
                        System.out.println("Bob received: " + new String(pt, StandardCharsets.UTF_8));
                        send("alice", "Message is intact".getBytes(StandardCharsets.UTF_8));
                    } else {
                        System.out.println("Message is corrupted");
                        send("alice", "Message is corrupted".getBytes(StandardCharsets.UTF_8));
                    }
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
