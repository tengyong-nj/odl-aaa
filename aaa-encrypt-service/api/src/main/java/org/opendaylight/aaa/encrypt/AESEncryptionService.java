package org.opendaylight.aaa.encrypt;

public interface AESEncryptionService {
    String encrypt(String data);
    String decrypt(String encryptedData);
}
