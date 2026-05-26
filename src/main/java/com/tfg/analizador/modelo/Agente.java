package com.tfg.analizador.modelo;

import java.util.Objects;

public class Agente {
    private String nombre;
    private String rol;

    public Agente(String nombre) {
        this.nombre = nombre;
        this.rol = "Desconocido"; 
    }

    public String getNombre() { return nombre; }
    public void setNombre(String nombre) { this.nombre = nombre; }

    public String getRol() { return rol; }
    public void setRol(String rol) { this.rol = rol; }

    // Para evitar duplicados en listas
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Agente agente = (Agente) o;
        return Objects.equals(nombre, agente.nombre);
    }

    @Override
    public int hashCode() {
        return Objects.hash(nombre);
    }
}