package org.example.authentification.facade;

import org.example.authentification.facade.exceptions.LoginDejaUtiliseException;
import org.example.authentification.facade.exceptions.UtilisateurInexistantException;
import org.example.authentification.modele.Utilisateur;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

@Component
public class FacadeUtilisateurs {

    private static long lastId = 0;

    private final Map<String, Utilisateur> utilisateursMap;
    private final Map<Long, Utilisateur> utilisateursMapById;
    private final PasswordEncoder delegatingPasswordEncoder;

    public FacadeUtilisateurs(PasswordEncoder delegatingPasswordEncoder) {
        this.utilisateursMapById = new HashMap<>();
        utilisateursMap = new HashMap<>();
        this.delegatingPasswordEncoder = delegatingPasswordEncoder;
    }

    public Utilisateur getUtilisateurById(Long id) throws UtilisateurInexistantException {
        if (utilisateursMapById.containsKey(id))
            return this.utilisateursMapById.get(id);
        else
            throw new UtilisateurInexistantException();
    }

    public Utilisateur getUtilisateurByEmail(String email) throws UtilisateurInexistantException {
        if (utilisateursMap.containsKey(email))
            return this.utilisateursMap.get(email);
        else
            throw new UtilisateurInexistantException();
    }

    public Utilisateur inscrireUtilisateur(String email, String password) throws LoginDejaUtiliseException {
        if (utilisateursMap.containsKey(email))
            throw new LoginDejaUtiliseException();
        else {
            Utilisateur utilisateur = new Utilisateur(++lastId,email, delegatingPasswordEncoder.encode(password));
            utilisateursMap.put(utilisateur.getEmail(), utilisateur);
            utilisateursMapById.put(utilisateur.getIdUtilisateur(), utilisateur);
            return utilisateur;
        }
    }

    public Collection<Utilisateur> getAllUtilisateurs() {
        return utilisateursMap.values();
    }

}
