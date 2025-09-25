package model;

import java.time.Instant;
import java.util.UUID;

public class KeyRecord {
    private final UUID keyId;
    private final int version;
    private final KeyStatus status;
    private final String value;
    private final Instant createdAt;

    public KeyRecord(UUID keyId, int version, KeyStatus status, String value, Instant createdAt) {
        this.keyId = keyId;
        this.version = version;
        this.status = status;
        this.value = value;
        this.createdAt = createdAt;
    }

    // getters

    public UUID getKeyId() {
        return keyId;
    }
    public int getVersion() {
        return version;
    }
    public KeyStatus getStatus() {
        return status;
    }
    public String getValue() {
        return value;
    }
    public Instant getCreatedAt() {
        return createdAt;
    }
}
