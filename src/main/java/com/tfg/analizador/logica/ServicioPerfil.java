package com.tfg.analizador.logica;

import org.mindrot.jbcrypt.BCrypt;

import com.tfg.analizador.modelo.Usuario;
import com.tfg.analizador.persistencia.GestorBBDD;

/**
 * Capa de servicio para operaciones del perfil de usuario.
 * Se mueve la lógica de BCrypt fuera del controlador y desacopla la
 * persistencia.
 */
public class ServicioPerfil {

    private final GestorBBDD gestorBD = new GestorBBDD();

    /**
     * Cambia la contraseña del usuario verificando primero la contraseña actual.
     * Lógica de BCrypt movida desde ControladorPerfil a la capa de
     * servicio.
     */
    public void cambiarContrasena(Usuario usuario, String contrasenaActual, String contrasenaNueva) throws Exception {
        if (usuario == null) {
            throw new Exception("No hay un usuario activo en la sesión.");
        }
        if (!BCrypt.checkpw(contrasenaActual, usuario.getHashPass())) {
            throw new Exception("La contraseña actual es incorrecta.");
        }
        String nuevoHash = BCrypt.hashpw(contrasenaNueva, BCrypt.gensalt());
        boolean exito = gestorBD.actualizarPassword(usuario.getIdUsuario(), nuevoHash);
        if (!exito) {
            throw new Exception("Error al actualizar la contraseña en la base de datos.");
        }
        // Actualizamos el hash en el objeto en memoria para mantener coherencia
        usuario.setHashPass(nuevoHash);
    }

    /**
     * Elimina la cuenta del usuario.
     */
    public boolean eliminarCuenta(int idUsuario) {
        return gestorBD.eliminarUsuario(idUsuario);
    }
}
