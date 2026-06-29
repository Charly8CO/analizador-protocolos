package com.tfg.analizador.modelo;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class Cifrado implements ElementoMensaje {
    private List<ElementoMensaje> contenido;
    private Clave claveSello;

    public Cifrado(Clave claveSello) {
        this.claveSello = claveSello;
        this.contenido = new ArrayList<>();
    }

    @Override
    public String getIdentificador() {
        return "Cifrado_con_" + claveSello.getIdentificador();
    }

    public Clave getClaveSello() {
        return claveSello;
    }

    public void setClaveSello(Clave claveSello) {
        this.claveSello = claveSello;
    }

    // Lista inmutable para proteger el encapsulamiento.
    public List<ElementoMensaje> getContenido() {
        return Collections.unmodifiableList(contenido);
    }

    public void anadirElemento(ElementoMensaje elemento) {
        this.contenido.add(elemento);
    }
}