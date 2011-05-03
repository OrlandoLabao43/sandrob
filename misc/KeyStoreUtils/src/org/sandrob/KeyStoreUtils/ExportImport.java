/**
 * Copyright (C) 2011 SandroB 
 * http://code.google.com/p/sandrob/ 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sandrob.KeyStoreUtils;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.Security;
import java.security.spec.KeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author sandrob
 * Utility to test encryption of data in sandrobView
 *
 */
public class ExportImport {

    private static String TAG = "ExportImport";
    
    // encoding used in Crypto string methods
    public static String CryptEncoding="UTF-8";
    // key algorithm
    private static String KeyAlgorithm = "AES";
    // key type
    private static String KeyFactoryType = "PBEWithSHA1And256BitAES-CBC-BC";
    // number of iterations for symmetric key generation
    private static int KeyGenIterations = 1000;
    // key length 
    private static int KeyLength = 256;
    // PreSalt length 
    private static int PreSaltLength = 16;
    // certificate file name
    private static String CertFileName = "cert.pfx";
    // database file name
    private static String DatabaseFileName = "sandrobView.db";
    //provider
    private static String CryptoProvider = "BC";
    
    
    private static Map<String, String> params = new HashMap<String, String>();
    static {
        params.put("action", "");
        params.put("password", "");
        params.put("filename", "");
        params.put("salt", "");
    }

    /**
     * Entry point
     * @param args
     */
    public static void main(String[] args) {
        try{
            if (args.length < params.size())
            {
                showUsage();
                return;
            }
            params.put("action", args[0]);
            params.put("password", args[1]);
            params.put("filename", args[2]);
            params.put("salt", args[3]);
            
            File file= new File(params.get("filename"));
            if (!file.exists()){
                Log.e(TAG, "Cannot access file:<" + params.get("filename") + ">");
                return;
            }
            // add BC as provider
            Security.addProvider(new BouncyCastleProvider());
            if (params.get("action").equalsIgnoreCase("decrypt")){
                actionDecrypt();
                Log.d(TAG,"Action passed");
                return;
            }
            if (params.get("action").equalsIgnoreCase("crypt")){
                actionCrypt();
                Log.d(TAG,"Action passed");
                return;
            }
            showUsage();
        }catch(Exception ex){
            Log.e(TAG, ex.getMessage());
            ex.printStackTrace();
        }
    }
    
    // Show usage helper
    private static void showUsage(){
        Log.e(TAG, "Usage: <action> <password> <filename> <salt>\n " +
                "e.g: ExportImport decrypt ssl sandrobView.db 415d7fd249bdb4d6b76e44713b38d71a" +
                "");
        return;
    }
    
    // crypt
    // TODO not tested yet
    private static void actionCrypt() throws Exception {
        // get pfx file
        BufferedInputStream in = new BufferedInputStream(new FileInputStream(params.get("filename")));
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream(); 
        byte[] data = new byte[4096];
        int numByteRead = in.read(data);
        while (numByteRead > 0){
            byteStream.write(data);
            numByteRead = in.read(data);
        }
        // encrypt
        byte[] encodedByteArray = encryptAes(byteStream.toByteArray(), params.get("password"));
        // make db connection
        Connection conn = makeDbConnection();
        
        //sql to update
        PreparedStatement stmt;
        stmt = conn.prepareStatement("UPDATE clientcertdata set data = ? WHERE _id = ?");
        stmt.setBytes(1, encodedByteArray);
        stmt.setInt(2, 1);
        // execute
        int rowsUpdated = stmt.executeUpdate();
        
        Log.d(TAG, "Rows updated : " + Integer.toString(rowsUpdated));
    }
    
    // make connection to sqlite database
    private static Connection makeDbConnection() throws Exception{
        Class.forName("org.sqlite.JDBC");
        String databaseFile = params.get("filename");
        Connection conn = DriverManager.getConnection("jdbc:sqlite:"+ databaseFile);
        return conn;
    }
    
    // decrypt
    private static void actionDecrypt() throws Exception{
        
        PreparedStatement stmt;
        ResultSet rs;
        int recordId = 1;
        Connection conn = makeDbConnection();
        stmt = conn.prepareStatement("SELECT data FROM clientcertdata WHERE _id = ?");
        // TODO this could be parameter from input
        stmt.setInt(1, recordId);
        
        rs = stmt.executeQuery();
        if (rs.next()) {
            BufferedOutputStream os;
            // get blob    
            byte[] blobByteArray = rs.getBytes(1);
            // get decoded bytes
            byte[] decodedByteArray = decryptAes(blobByteArray, params.get("password"));
            
            os = new BufferedOutputStream(new FileOutputStream(CertFileName));
            os.write(decodedByteArray, 0, decodedByteArray.length);
            os.flush();
            os.close();
        }else{
            Log.e(TAG, "There is no record with id=" + Integer.toString(recordId));
        }
    }
    
    private static byte[] decryptAes(byte[] input, String password) throws Exception{
        return process(input, password, false);
    }
    
    private static byte[] encryptAes(byte[] input, String password) throws Exception{
        return process(input, password, true);
    }

    private static byte[] process(byte[] input, String password, boolean forEncryption) throws Exception {
        try{
            // generate key with iteration from password, salt
            SecretKeyFactory f = SecretKeyFactory.getInstance(KeyFactoryType, CryptoProvider);
            KeySpec ks = new PBEKeySpec(password.toCharArray(), getSaltByteArray(), KeyGenIterations, KeyLength);
            SecretKey s = f.generateSecret(ks);
            Key k = new SecretKeySpec(s.getEncoded(), KeyAlgorithm);
            CipherParameters cipherParameters = new KeyParameter(k.getEncoded());
            BlockCipher blockCipher = new AESEngine();
            BlockCipherPadding blockCipherPadding = new PKCS7Padding();
            BufferedBlockCipher bufferedBlockCipher = new PaddedBufferedBlockCipher(blockCipher, blockCipherPadding);
            
            // initialize the chiper
            bufferedBlockCipher.init(forEncryption, cipherParameters);
    
            int inputOffset = 0;
            int inputLength = input.length;
    
            int maximumOutputLength = bufferedBlockCipher.getOutputSize(inputLength);
            byte[] output = new byte[maximumOutputLength];
            int outputOffset = 0;
            int outputLength = 0;
    
            int bytesProcessed;
    
            // process input buffer
            bytesProcessed = bufferedBlockCipher.processBytes(
                    input, inputOffset, inputLength,
                    output, outputOffset
                );
            outputOffset += bytesProcessed;
            outputLength += bytesProcessed;
    
            // process the last block
            bytesProcessed = bufferedBlockCipher.doFinal(output, outputOffset);
            outputOffset += bytesProcessed;
            outputLength += bytesProcessed;
    
            if (outputLength == output.length) {
                return output;
            } else {
                byte[] truncatedOutput = new byte[outputLength];
                System.arraycopy(
                        output, 0,
                        truncatedOutput, 0,
                        outputLength
                    );
                return truncatedOutput;
            }
        }catch (Exception ex){
            Log.e(TAG, ex.getMessage());
            throw new Exception(ex);
        }
    }
    
    // it initialize device specific salt 
    // android_id + fixedSalt from once generated with SecureRandom
    private static byte[] getSaltByteArray() throws Exception{
        // device id
        ByteArrayOutputStream streamSalt = new ByteArrayOutputStream();
        
        // on emulator is this "android_id" otherwise specific to phone
        // String stringDeviceId = android.provider.Settings.Secure.ANDROID_ID;
        String stringDeviceId = "android_id";
        
        // this should be used to generate fixed before make it public
        // PreSaltLength should be bigger here is small to fit command line 
        // byte[] bytePreSalt = new byte[PreSaltLength];
        // fixed from random generator
        // SecureRandom random = new SecureRandom();
        // random.nextBytes(bytePreSalt);
        // String stringPreSalt = byteArr2HexStr(bytePreSalt);
        String stringPreSalt = params.get("salt");
        
        Log.d(TAG, "PreSalt as hex String:" + stringPreSalt);
        streamSalt.write(stringDeviceId.getBytes(CryptEncoding));
        streamSalt.write(str2Bytes(stringPreSalt));
        return streamSalt.toByteArray();
    }
    
    // Converts from byte array to hex string
    // used mainly for logging
    private static String byte2Str(byte[] bytes) {
        StringBuffer stringBuffer = new StringBuffer(bytes.length * 2);
        for (int b : bytes) {
            if (b < 0){
                b = b + 256;
            }
            if (b < 16){
                stringBuffer.append("0");
            }
            stringBuffer.append(Integer.toString(b, 16));
        }
        return stringBuffer.toString();
    }

    // Converts from hex string to byte array
    private static byte[] str2Bytes(String str) {
        int length = str.length();
        byte[] bytes = new byte[length / 2];
        for (int i = 0; i < length; i = i + 2) {
            String subString = str.substring(i, i + 2);
            bytes[i / 2] = (byte) Integer.parseInt(subString, 16);
        }
        return bytes;
    }
}
