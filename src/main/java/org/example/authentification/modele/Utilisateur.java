package org.example.authentification.modele;

public class Utilisateur {

    private final String email;
    private final String password;
    private final Long idUtilisateur;

    public Utilisateur(Long id ,String email, String password) {
        idUtilisateur = id;
        this.email = email;
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public Long getIdUtilisateur() {
        return idUtilisateur;
    }

    public String getPassword() {
        return password;
    }
}
