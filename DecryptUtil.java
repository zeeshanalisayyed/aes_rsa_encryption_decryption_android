package com.zee.uedecryptutil;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

class DecryptUtil {

	private static String keezPath = "D:\\zee\\keys\\";
	private static String sourcePath = "D:\\zee\\files\\encrypted";
	private static String destPath = "D:\\zee\\files\\decrypted\\";
	
	public static void main(String[] args) throws IOException {
		// TODO Auto-generated method stub
		createDirectories();
		
		File file = new File(sourcePath);
		File parentFile = file.getParentFile();
		
		if(!parentFile.exists()){
			parentFile.mkdirs();
		}
		
		if(file.exists()) decryptAndSaveFiles(file);
	}
	
	private static void createDirectories(){
		File encDir = new File(sourcePath);
		File decDir = new File(destPath);
		File keezDir = new File(sourcePath);
		if(!encDir.exists() && !decDir.exists() && !keezDir.exists()){
			encDir.mkdirs();
			decDir.mkdirs();
			keezDir.mkdirs();
		}
	}
	
	private static void decryptAndSaveFiles(File folder) throws IOException{
		byte secretKeyBytes[] = loadSecretKey();
		PrivateKey privateKey = loadPrivateKey();
		
		if(secretKeyBytes != null && privateKey != null){
			byte[] secretKeyDecrypted = DecryptUtil.decryptSecKeyToBytes(secretKeyBytes, privateKey);
			for(File f : folder.listFiles()){
				if(f != null && f.exists() && f.isFile()){
					System.out.println("File decrypted ===== " + f.getAbsolutePath());
					byte[] bytesArray = new byte[(int) f.length()];
					FileInputStream fis = new FileInputStream(f);
					fis.read(bytesArray);
					byte[] fileBytes = DecryptUtil.decodeFile(secretKeyDecrypted, bytesArray);
					
					DateFormat dateFormat = new SimpleDateFormat("dd-MM-yyyy_HH-mm-ss");
					Date date = new Date();
					File file = new File(destPath+dateFormat.format(date)+"_dec_"+f.getName());
					File parentFile = file.getParentFile();
					if(!parentFile.exists()){
						parentFile.mkdirs();
					}
					
					if(parentFile.exists()){
						FileOutputStream fos = new FileOutputStream(file);
						fos.write(fileBytes);
						fos.close();
						fis.close();	
					}	
				} else{
					System.out.println("File is null!!");
				}
			}	
		} else{
			System.out.println("keez are not present!!");
		}
	}
	
	public static byte[] decodeFile(byte[] key, byte[] fileData) {
		SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
		byte[] decrypted = null;
		try {
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.DECRYPT_MODE, skeySpec);
			decrypted = cipher.doFinal(fileData);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch(Exception e){
			// for all other exception
			e.printStackTrace();
		}
	    return decrypted;
    }
	
	public static byte[] decryptSecKeyToBytes(byte[] secretKey, PrivateKey privateKey) {
        byte[] secretKeyBytesDecrypted = null;
        try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, privateKey );
			secretKeyBytesDecrypted = cipher.doFinal(secretKey);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch(Exception e){
			// for all other exception
			e.printStackTrace();
		}
        return secretKeyBytesDecrypted;
    }
	
	private static byte[] loadSecretKey() throws IOException{
		File file = new File(keezPath + "SecKey.pem");
		File parentFile = file.getParentFile();
		if(!parentFile.exists()){
			parentFile.mkdirs();
		}
		
		if(file.exists()){
			FileInputStream readStream = new FileInputStream(file);
			DataInputStream dis = new DataInputStream(readStream);
			byte secretKeyBytes[] = new byte[(int) file.length()];
			dis.readFully(secretKeyBytes);
			dis.close();
			readStream.close();
			return secretKeyBytes;	
		} else{
			return null;
		}
	}

	private static PrivateKey loadPrivateKey() {
		File filePrivateKey = new File(keezPath + "privateKey.pem");
		File parentFile = filePrivateKey.getParentFile();
		if(!parentFile.exists()){
			parentFile.mkdirs();
		}
		
		if(!filePrivateKey.exists()){
			return null;
		}
		
		PrivateKey privateKey = null;
		try {
			FileInputStream fis = new FileInputStream(filePrivateKey);
			DataInputStream dis = new DataInputStream(fis);
			byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
			dis.readFully(encodedPrivateKey);
			dis.close();
			fis.close();
			
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
			privateKey = keyFactory.generatePrivate(privateKeySpec);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch(Exception e){
			// for all other exception
			e.printStackTrace();
		}
		
		return privateKey;
	}
}
