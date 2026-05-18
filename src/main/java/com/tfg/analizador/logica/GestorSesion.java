package com.tfg.analizador.logica;

import com.tfg.analizador.modelo.Usuario;

public class GestorSesion {

    private static GestorSesion instancia;
    private Usuario usuarioActivo;

    // Constructor privado para impedir instanciaciones externas descontroladas
    private GestorSesion() {}

    public static GestorSesion getInstancia() {
        if (instancia == null) {
            instancia = new GestorSesion();
        }
        return instancia;
    }

    public void iniciarSesion(Usuario u) {
        this.usuarioActivo = u;
        System.out.println("Sesión global inicializada para: " + u.getNombreUsuario());
    }

    public void cerrarSesion() {
        if (usuarioActivo != null) {
            System.out.println("Cerrando sesión de: " + usuarioActivo.getNombreUsuario());
            this.usuarioActivo = null;
        }
    }

    public Usuario getUsuarioActivo() {
        return this.usuarioActivo;
    }
}