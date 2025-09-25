package model;

public interface AesBlock {
    void setKey(byte[] key);
    void encryptKey(byte[] in, int inOff, byte[] out, int outOff);
    void decryptKey(byte[] in, int inOff, byte[] out, int outOff);
}
