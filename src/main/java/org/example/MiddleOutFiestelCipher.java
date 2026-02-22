package org.example;

import org.example.Exceptions.InvalidKeyException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

public class MiddleOutFiestelCipher {

    private final String MASTER_KEY;

    public MiddleOutFiestelCipher(String masterKey) {
        MASTER_KEY = masterKey;
    }

    public String encrypt(String password, String initializer) {
        byte[] key;
        try {
            key = hashMasterKey(initializer);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        byte[] passwordBytes = getPasswordBytes(password);
        byte[] encryptedPasswordBytes = new byte[passwordBytes.length];

        for ( int i = 0; i < passwordBytes.length / 8; i++ ) {
            byte[] eightByteArray = Arrays.copyOfRange(passwordBytes, i * 8, i * 8 + 8);
            int pointerLeft = 3;
            int pointerRight = 4;
            byte[] innerArray = new byte[4];
            byte[] outerArray = new byte[4];
            int index;
            for ( int j = 0; j < innerArray.length / 2; j++ ) {
                index = j * 2;
                innerArray[index] = eightByteArray[pointerLeft];
                innerArray[index + 1] = eightByteArray[pointerRight];
                pointerLeft--;
                pointerRight++;
            }
            for ( int j = 0; j < outerArray.length / 2; j++ ) {
                index = j * 2;
                outerArray[index] = eightByteArray[pointerLeft];
                outerArray[index + 1] = eightByteArray[pointerRight];
                pointerLeft--;
                pointerRight++;
            }
            byte[] encryptedEightByteArray = applyFiestelCipher(innerArray, outerArray, key, false);
            System.arraycopy(encryptedEightByteArray,0,encryptedPasswordBytes,i * 8, 8);
        }
        return Base64.getEncoder().encodeToString(encryptedPasswordBytes);
    }

    public String decrypt(String initializer, String encryptedPassword) throws InvalidKeyException {
        byte[] key;
        try {
            key = hashMasterKey(initializer);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        byte[] encryptedPasswordBytes = Base64.getDecoder().decode(encryptedPassword);

        for ( int i = 0; i < encryptedPasswordBytes.length / 8; i++ ) {
            byte[] eightByteArray = Arrays.copyOfRange(encryptedPasswordBytes, i * 8, i * 8 + 8);
            int pointerLeft = 3;
            int pointerRight = 4;
            byte[] innerArray = new byte[4];
            byte[] outerArray = new byte[4];
            int index;
            for ( int j = 0; j < innerArray.length / 2; j++ ) {
                index = j * 2;
                innerArray[index] = eightByteArray[pointerLeft];
                innerArray[index + 1] = eightByteArray[pointerRight];
                pointerLeft--;
                pointerRight++;
            }
            for ( int j = 0; j < outerArray.length / 2; j++ ) {
                index = j * 2;
                outerArray[index] = eightByteArray[pointerLeft];
                outerArray[index + 1] = eightByteArray[pointerRight];
                pointerLeft--;
                pointerRight++;
            }
            byte[] decryptedEightByteArray = applyFiestelCipher(innerArray, outerArray, key, true);
            System.arraycopy(decryptedEightByteArray,0,encryptedPasswordBytes,i * 8, 8);
        }
        byte[] passwordBytes = removePadding(encryptedPasswordBytes);
        return new String(passwordBytes, StandardCharsets.UTF_8);
    }

    private byte[] hashMasterKey(String initializer) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        String keyString = MASTER_KEY + initializer;
        return digest.digest(keyString.getBytes(StandardCharsets.UTF_8));
    }

    private byte[] getPasswordBytes(String password) {
        byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);

        int length = passwordBytes.length;
        int paddingLength = 8 - ( length % 8 );

        passwordBytes = Arrays.copyOf(passwordBytes, length + paddingLength);

        for ( int i = length; i < passwordBytes.length; i++ ) {
            passwordBytes[i] = (byte) paddingLength;
        }

        return passwordBytes;
    }

    private byte[] removePadding(byte[] encryptedPasswordBytes) throws InvalidKeyException {
        int paddingLength = encryptedPasswordBytes[encryptedPasswordBytes.length - 1] & 0xFF;
        if ( paddingLength > 8 || paddingLength == 0) {
            throw new InvalidKeyException("Bad Padding");
        }
        return Arrays.copyOfRange(encryptedPasswordBytes, 0, encryptedPasswordBytes.length - paddingLength);
    }

    private byte[] applyFiestelCipher(byte[] innerArray, byte[] outerArray, byte[] key, boolean isDecryption) {
        byte[][] roundKeys = new byte[16][4];

        for ( int i = 0; i < 16; i++ ){
            if ( !isDecryption ) {
                roundKeys[i] = Arrays.copyOfRange(key, i * 4, i * 4 + 4);
            } else {
                roundKeys[i] = Arrays.copyOfRange(key, (15 - i) * 4, (15 - i) * 4 + 4);
            }

            byte[] fOut = fFunction(innerArray, roundKeys[i]);
            byte[] newInner = new byte[4];
            for ( int j = 0; j < 4; j++ ) {
                newInner[j] = (byte) (outerArray[j] ^ fOut[j]);
            }
            if ( i != 15 ) {
                outerArray = Arrays.copyOf(innerArray, innerArray.length);
                innerArray = Arrays.copyOf(newInner, newInner.length);
            } else {
                outerArray = newInner;
            }
        }

        byte[] eightByteArray = new byte[8];
        int pointerLeft = 3;
        int pointerRight = 4;
        int index;
        for ( int j = 0; j < innerArray.length / 2; j++ ) {
            index = j * 2;
            eightByteArray[pointerLeft] = innerArray[index];
            eightByteArray[pointerRight] = innerArray[index + 1];
            pointerLeft--;
            pointerRight++;
        }
        for ( int j = 0; j < outerArray.length / 2; j++ ) {
            index = j * 2;
            eightByteArray[pointerLeft] = outerArray[index];
            eightByteArray[pointerRight] = outerArray[index + 1];
            pointerLeft--;
            pointerRight++;
        }
        return eightByteArray;
    }

    private byte[] fFunction(byte[] inner, byte[] key) {
        byte[] fOut = new byte[4];
        for ( int j = 0; j < 4; j++ ){
            int data = inner[j] & 0xFF;
            int keyValue = key[j] & 0xFF;
            int sum = data + keyValue;
            int wrappedSum = sum & 0xFF;
            int scramble = (( wrappedSum << 3 ) | ( wrappedSum >>> 5 )) & 0xFF;
            fOut[j] = (byte) scramble;
        }
        fOut[1] = (byte) (fOut[1] ^ fOut[0]);
        fOut[2] = (byte) (fOut[2] ^ fOut[1]);
        fOut[3] = (byte) (fOut[3] ^ fOut[2]);

        return fOut;
    }

}
