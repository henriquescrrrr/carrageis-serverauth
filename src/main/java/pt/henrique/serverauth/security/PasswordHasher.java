package pt.henrique.serverauth.security;

public interface PasswordHasher {
    String hash(String plaintext);

    boolean verify(String plaintext, String hash);
}
