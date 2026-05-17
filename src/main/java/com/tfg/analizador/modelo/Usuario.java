package com.tfg.analizador.modelo;

public class Usuario {

    private int idUsuario;
    private String nombreUsuario;
    private String hashPass;

    public Usuario() {}

    // Creamos los usuarios nuevos desde la interfaz y el id lo crea el sqlite
    public Usuario(String nombre_usuario, String hash_pass) {
        this.nombreUsuario = nombre_usuario;
        this.hashPass = hash_pass;
    }

    public int getIdUsuario() { return idUsuario; }
    public String getNombreUsuario() { return nombreUsuario; }
    public String getHashPass() { return hashPass; }

    public void setIdUsuario(int id_usuario) { this.idUsuario = id_usuario; }
    public void setNombreUsuario(String nombre_usuario) { this.nombreUsuario = nombre_usuario; }
    public void setHashPass(String hash_pass) { this.hashPass = hash_pass; }

    public boolean actualizarContrase(String nuevohash) {
        // TODO
        throw new UnsupportedOperationException();
    }
}