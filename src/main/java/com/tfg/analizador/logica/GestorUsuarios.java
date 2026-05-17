package com.tfg.analizador.logica;

import java.sql.SQLException;

import org.mindrot.jbcrypt.BCrypt;

import com.tfg.analizador.modelo.Usuario;
import com.tfg.analizador.persistencia.GestorBBDD;

public class GestorUsuarios {

    public void registrarNuevoUsuario(String email, String passwordPlana) throws Exception {
        //Generamos el Hash
        String hashSeguro = BCrypt.hashpw(passwordPlana, BCrypt.gensalt());
        
        // Empaquetamos el modelo
        Usuario nuevoUsuario = new Usuario(email, hashSeguro);
        
        // Conectamos con la base de datos
        GestorBBDD gestorBD = new GestorBBDD();
        
        try {
            gestorBD.guardarUsuario(nuevoUsuario);
        } catch (SQLException e) {
            // El código 19 en SQLite significa que el usuario ya existe
            if (e.getErrorCode() == 19 || e.getMessage().contains("UNIQUE constraint failed")) {
                throw new Exception("Ese correo electrónico ya está registrado.");
            } else {
                throw new Exception("Error interno del servidor: " + e.getMessage());
            }
        }
    }
}