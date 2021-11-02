package org.opendaylight.aaa.encrypt.impl;

import org.opendaylight.aaa.encrypt.AESEncryptionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class AESEncryptionServiceImpl implements AESEncryptionService {
    private static final Logger LOG = LoggerFactory.getLogger(AESEncryptionServiceImpl.class);
    private static final String DEFAULT_CONFIG_FILE_PATH = "etc" + File.separator + "opendaylight" + File.separator
            + "datastore" + File.separator + "initial" + File.separator + "config" + File.separator
            + "aaa-encrypt-service-config.xml";
    static{
        java.security.Security.setProperty("crypto.policy", "unlimited");
    }
    private final SecretKey key;
    private final IvParameterSpec ivspec;
    private  final Cipher encryptCipher;
    private final Cipher decryptCipher;
    private final String encryptKey;
    private final int passwordLength;
    private final String encryptSalt;
    private final String encryptType;
    private final int encryptIterationCount;
    private final String cipherTransforms;
    private final String encryptMethod;
    private final int encryptKeyLength;

    public AESEncryptionServiceImpl(){
        SecretKey tempKey = null;
        IvParameterSpec tempIvSpec = null;
        Document doc = getConfigElements();
        if(doc==null){
            encryptKey = "fBaUx89vFKkDKb284d7NjkFoNcKWBAkf";
            passwordLength = 12;
            encryptSalt = "TdtWeHbch/7xP52/rp3Usw==";
            encryptMethod = "PBKDF2WithHmacSHA1";
            encryptType = "AES";
            encryptKeyLength = 256;
            encryptIterationCount = 32768;
            cipherTransforms = "AES/CBC/PKCS5Padding";

        }else {
            final Node keyNode = doc.getElementsByTagName("encrypt-key").item(0);
            final Node salt = doc.getElementsByTagName("encrypt-salt").item(0);
            final Node passwordLengthNode = doc.getElementsByTagName("password-length").item(0);
            final Node encryptTypeNode = doc.getElementsByTagName("encrypt-type").item(0);
            final Node iterationCountNode = doc.getElementsByTagName("encrypt-iteration-count").item(0);
            final Node methodMode = doc.getElementsByTagName("encrypt-method").item(0);
            final Node transformsNode = doc.getElementsByTagName("cipher-transforms").item(0);
            final Node keyLengthNode = doc.getElementsByTagName("encrypt-key-length").item(0);

            encryptKey = keyNode.getTextContent();
            passwordLength =Integer.parseInt(passwordLengthNode.getTextContent());
            encryptSalt = salt.getTextContent();
            encryptMethod = methodMode.getTextContent();
            encryptType = encryptTypeNode.getTextContent();
            encryptKeyLength = Integer.parseInt(keyLengthNode.getTextContent());
            encryptIterationCount = Integer.parseInt(iterationCountNode.getTextContent());
            cipherTransforms = transformsNode.getTextContent();
           // initializeConfigDataTree(encrySrvConfig,dataBroker);
        }
        LOG.debug("current key length is {},key is {}",encryptKeyLength,encryptKey);
        final byte[] enryptionKeySalt = Base64.getDecoder().decode(encryptSalt);
        try{
            final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(encryptMethod);
            final KeySpec spec = new PBEKeySpec(encryptKey.toCharArray(), enryptionKeySalt,
                    encryptIterationCount, encryptKeyLength);
            tempKey = keyFactory.generateSecret(spec);
            tempKey = new SecretKeySpec(tempKey.getEncoded(), encryptType);
            tempIvSpec = new IvParameterSpec(enryptionKeySalt);

        }catch (NoSuchAlgorithmException | InvalidKeySpecException e){
            LOG.error("Failed to initialize secret key", e);
        }
        key = tempKey;
        ivspec = tempIvSpec;
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(cipherTransforms);
            cipher.init(Cipher.ENCRYPT_MODE, key, ivspec);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException
                | InvalidKeyException e) {
            LOG.error("Failed to create encrypt cipher.", e);
        }
        this.encryptCipher = cipher;
        cipher = null;
        try {
            cipher = Cipher.getInstance(cipherTransforms);
            cipher.init(Cipher.DECRYPT_MODE, key, ivspec);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException
                | InvalidKeyException e) {
            LOG.error("Failed to create decrypt cipher.", e);
        }
        this.decryptCipher = cipher;

    }
    @Override
    public  String encrypt(String data) {
        try{

            if (key == null) {
                LOG.warn("Encryption Key is NULL, will not encrypt data.");
                return data;
            }
            try {
                synchronized (encryptCipher) {
                    byte[] cryptobytes = encryptCipher.doFinal(data.getBytes(Charset.defaultCharset()));
                    String cryptostring = DatatypeConverter.printBase64Binary(cryptobytes);
                    return cryptostring;
                }
            } catch (IllegalBlockSizeException | BadPaddingException e) {
                LOG.error("Failed to encrypt data.", e);
            }
            return data;


        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }
    @Override
    public  String decrypt(String encryptedData) {
        try{
            if (key == null || encryptedData == null || encryptedData.length() == 0) {
                LOG.warn("String {} was not decrypted.", encryptedData);
                return encryptedData;
            }
            try {
                byte[] cryptobytes = DatatypeConverter.parseBase64Binary(encryptedData);
                byte[] clearbytes = decryptCipher.doFinal(cryptobytes);
                return new String(clearbytes, Charset.defaultCharset());
            } catch (IllegalBlockSizeException | BadPaddingException e) {
                LOG.error("Failed to decrypt encoded data", e);
            }
            return encryptedData;

        }catch (Exception e){
            e.printStackTrace();
        }
        return null;

    }
    private static Document getConfigElements() {
        try {

            final File configFile = new File(DEFAULT_CONFIG_FILE_PATH);
            if (configFile.exists()) {
                final DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
                final DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
                final Document doc = docBuilder.parse(configFile);
                return doc;

            } else {
                LOG.warn("The encryption service config file does not exist {}", DEFAULT_CONFIG_FILE_PATH);
            }
        } catch (ParserConfigurationException  | SAXException | IOException e) {
            LOG.error("Error while updating the encryption service config file", e);
        }
        return null;
    }
}
