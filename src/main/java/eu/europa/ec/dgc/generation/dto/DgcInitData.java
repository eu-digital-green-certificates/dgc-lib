package eu.europa.ec.dgc.generation.dto;

public class DgcInitData {

    private String issuerCode;
    private long issuedAt;
    private long expriation;
    private int algId;
    private byte[] keyId;
    /**
     * if true the whole cose unsigned data are encrypted.
     * if false only the cwt cbor data are encrypted
     */
    private boolean encryptCose = false;

    public String getIssuerCode() {
        return issuerCode;
    }

    public void setIssuerCode(String issuerCode) {
        this.issuerCode = issuerCode;
    }

    public long getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(long issuedAt) {
        this.issuedAt = issuedAt;
    }

    public long getExpriation() {
        return expriation;
    }

    public void setExpriation(long expriation) {
        this.expriation = expriation;
    }

    public int getAlgId() {
        return algId;
    }

    public void setAlgId(int algId) {
        this.algId = algId;
    }

    public byte[] getKeyId() {
        return keyId;
    }

    public void setKeyId(byte[] keyId) {
        this.keyId = keyId;
    }

    public boolean isEncryptCose() {
        return encryptCose;
    }

    public void setEncryptCose(boolean encryptCose) {
        this.encryptCose = encryptCose;
    }
}
