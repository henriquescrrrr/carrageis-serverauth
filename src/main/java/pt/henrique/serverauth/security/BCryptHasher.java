package pt.henrique.serverauth.security;

import org.mindrot.jbcrypt.BCrypt;

public final class BCryptHasher implements PasswordHasher {

    private final int cost;

    public BCryptHasher(int cost) {
        this.cost = cost;
    }

    @Override
    public String hash(String plaintext) {
        return BCrypt.hashpw(plaintext, BCrypt.gensalt(cost));
    }

    @Override
    public boolean verify(String plaintext, String hash) {
        if (hash == null || hash.isBlank()) return false;
        return BCrypt.checkpw(plaintext, hash);
    }
}

