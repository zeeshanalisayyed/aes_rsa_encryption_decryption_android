package com.zee.utilities;

import android.util.Base64;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class EncryptionUtil {

    public static byte[] generateAesSecretKey(){
        String SALT2 = "strong_salt_value";
        String username = "user_name";
        String password = "strong_password";
        byte[] key = (SALT2 + username + password).getBytes();
        SecretKey secretKeySpec = null;

        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16); // use only first 128 bit
            secretKeySpec = new SecretKeySpec(key, "AES");
        } catch (Exception e) { // ideally NoSuchAlgorithmException
            e.printStackTrace();
        }
        return secretKeySpec != null ? secretKeySpec.getEncoded() : null;
    }

    public static byte[] encodeFile(byte[] key, byte[] fileData) {
        SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
        byte[] encrypted = null;
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
            encrypted = cipher.doFinal(fileData);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (Exception e){
            e.printStackTrace();
        }
        return encrypted;
    }

    public static byte[] encryptSecretKey(byte skey[], Context context) {
        byte[] encryptedSecretKey = null;
        try {
            PublicKey publicKey = loadPublicKey(SharedPrefUtil.getPublicKey(context));
            if(publicKey == null) return null;
            // initialize the cipher with the user's public key
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            encryptedSecretKey = cipher.doFinal(skey);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (Exception e){
            e.printStackTrace();
        }
        return encryptedSecretKey;
    }

    private static PublicKey loadPublicKey(String stored) {
        if(stored == null) return null;
        byte[] data = Base64.decode(stored, Base64.URL_SAFE); // issue: cause
        X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
        try {
            KeyFactory fact = KeyFactory.getInstance("RSA");
            return fact.generatePublic(spec);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }
}
