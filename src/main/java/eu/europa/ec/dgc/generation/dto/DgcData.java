package eu.europa.ec.dgc.generation.dto;

public class DgcData {

    private byte[] dek;
    /**
     * encrypted dcc cwt (cbor payload) data (cose array item 2)
     */
    private byte[] dataEncrypted;
    private byte[] hash;
    /**
     * unsigned dcc COSE data.
     */
    private byte[] dccData;

    public byte[] getDek() {
        return dek;
    }

    public void setDek(byte[] dek) {
        this.dek = dek;
    }

    public byte[] getDataEncrypted() {
        return dataEncrypted;
    }

    public void setDataEncrypted(byte[] dataEncrypted) {
        this.dataEncrypted = dataEncrypted;
    }

    public byte[] getHash() {
        return hash;
    }

    public void setHash(byte[] hash) {
        this.hash = hash;
    }

    public byte[] getDccData() {
        return dccData;
    }

    public void setDccData(byte[] dccData) {
        this.dccData = dccData;
    }
}
