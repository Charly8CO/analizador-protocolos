package com.tfg.analizador.logica;

/**
 * Excepción para errores relacionados con autenticación y gestión de usuarios.
 */
public class UsuarioException extends AnalizadorException {
    public UsuarioException(String mensaje) {
        super(mensaje);
    }
}
