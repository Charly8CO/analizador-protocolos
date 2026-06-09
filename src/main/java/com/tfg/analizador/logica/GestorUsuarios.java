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

    public Usuario autenticarUsuario(String email, String contraPlana) throws Exception{

        GestorBBDD gestor = new GestorBBDD();

        //Obtenemos usuario
        Usuario usuarioBD = gestor.obtenerUsuarioEmail(email);

        // Se comprueba que el usuario esté registrado
        if(usuarioBD == null) throw new Exception("El usuario no está registrado");

        //Se comprueba que los hashes sean iguales
        if(!BCrypt.checkpw(contraPlana, usuarioBD.getHashPass())) throw new Exception("La contraseña es incorrecta");

        return usuarioBD;

    }

    public boolean existeUsuario(String email) throws Exception {
        GestorBBDD gestor = new GestorBBDD();
        return gestor.obtenerUsuarioEmail(email) != null;
    }

    public void actualizarContrasena(String email, String nuevaContraPlana) throws Exception {
        GestorBBDD gestor = new GestorBBDD();
        Usuario u = gestor.obtenerUsuarioEmail(email);
        
        if (u == null) throw new Exception("El usuario no está registrado.");
        
        String hashSeguro = BCrypt.hashpw(nuevaContraPlana, BCrypt.gensalt());
        
        boolean actualizado = gestor.actualizarPassword(u.getIdUsuario(), hashSeguro);
        
        if (!actualizado) {
            throw new Exception("Error crítico: No se pudo guardar la contraseña en la Base de Datos.");
        }
    }
}