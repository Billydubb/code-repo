package com.softgarden.jhreact;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.spongycastle.jce.*;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.SecureRandom;

import org.spongycastle.crypto.engines.AESEngine;
import org.spongycastle.crypto.modes.CBCBlockCipher;
import org.spongycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;

import java.io.UnsupportedEncodingException;

import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;

import java.util.Map;
import java.util.HashMap;
import java.util.Arrays;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.WritableNativeArray;
import com.facebook.react.bridge.WritableArray;
import android.util.Base64;

public class EncryptionModule extends ReactContextBaseJavaModule{

    public EncryptionModule(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @Override
    public String getName(){
      return "EncryptionModule";
    }

    @ReactMethod
    public void pbdkf2(String password, String salt, int iterationCount, int keyLengthInBits, Promise promise) {

        try{
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1", "SC");

            byte[] saltArr = salt.getBytes();
            // int iterationCount = iteractionCount;
            // int keyLength = 512;
            KeySpec keySpec = new PBEKeySpec(password.toCharArray(), saltArr, iterationCount, keyLengthInBits);
            Key key = keyFactory.generateSecret(keySpec);

            byte[] encodedDerivedKey = key.getEncoded();
            String arrayAsString = Arrays.toString(encodedDerivedKey);

            WritableArray wArr = new WritableNativeArray();
            
            for(byte val : encodedDerivedKey) {
                wArr.pushInt(val);
            }
            promise.resolve(wArr);
            

        }catch(NoSuchAlgorithmException exc){
            System.out.println("NO SUCH ALGORITHM");
        } catch(NoSuchProviderException exc) {
            System.out.println("NO SUCH PROVIDER");
        } catch(InvalidKeySpecException exc) {
            System.out.println("NO SUCH PROVIDER");
        } catch(Exception exc) {
          System.out.println("SOMETHING WENT WRONG IN THE NATIVE MODULE");
          promise.reject("SOMETHING WENT WRONG IN THE NATIVE MODULE", exc);
        }


    }

    @ReactMethod
    public void getRandomIv(Promise promise){
        SecureRandom rng = new SecureRandom();
        byte[] ivBytes = new byte[16];
        rng.nextBytes(ivBytes);
            
        String ivBase64 = Base64.encodeToString(ivBytes, Base64.NO_WRAP);
        promise.resolve(ivBase64);
    }

    @ReactMethod
    public void encryptWithAes(String keyHex, String clearText, String ivBytesBase64, Promise promise)
    {
        try
        {   
            //byte[] key = Base64.decode(keyBase64, Base64.NO_WRAP);
            byte[] key = this.hexStringToByteArray(keyHex);
            byte[] clear = clearText.getBytes("UTF-8");
            byte[] ivBytes= Base64.decode(ivBytesBase64, Base64.NO_WRAP);


            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));

            cipher.init(true, new ParametersWithIV(new KeyParameter(key), ivBytes));
            byte[] outBuf   = new byte[cipher.getOutputSize(clear.length)];

            int processed = cipher.processBytes(clear, 0, clear.length, outBuf, 0);
            processed += cipher.doFinal(outBuf, processed);

            byte[] outBuf2 = new byte[processed + 16];        // Make room for iv
            System.arraycopy(ivBytes, 0, outBuf2, 0, 16);    // Add iv
            System.arraycopy(outBuf, 0, outBuf2, 16, processed);    // Then the encrypted data

            final String encryptedB64 = Base64.encodeToString(outBuf2, Base64.NO_WRAP);

            //System.out.println(encryptedB64);

            promise.resolve(encryptedB64);

            //return encryptedB64;
        }
        catch(Exception e)
        {
            e.printStackTrace();
            promise.reject(e);
        }
    }

    @ReactMethod
    public void decryptWithAes(String keyHex, String encryptedBase64, Promise promise)
    {
        try
        {
            //byte[] key = Base64.decode(keyBase64, Base64.NO_WRAP);
            byte[] key = this.hexStringToByteArray(keyHex);
            final byte[] encrypted = Base64.decode(encryptedBase64, Base64.NO_WRAP);

            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
            byte[] ivBytes = new byte[16];
            System.arraycopy(encrypted, 0, ivBytes, 0, ivBytes.length); // Get iv from data
            byte[] dataonly = new byte[encrypted.length - ivBytes.length];
            System.arraycopy(encrypted, ivBytes.length, dataonly, 0, encrypted.length   - ivBytes.length);

            cipher.init(false, new ParametersWithIV(new KeyParameter(key), ivBytes));
            byte[] clear = new byte[cipher.getOutputSize(dataonly.length)];
            System.out.println(cipher.getOutputSize(dataonly.length));
            int len = cipher.processBytes(dataonly, 0, dataonly.length, clear,0);
            len += cipher.doFinal(clear, len);


            final String decryptedString = new String(clear).substring(0, len);

            promise.resolve(decryptedString);


            //return decryptedString;
        }
        catch(Exception e)
        {
            e.printStackTrace();
            promise.reject(e);
        }
    }

    private byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                + Character.digit(s.charAt(i+1), 16));
        }
        return data;
}

    


}
