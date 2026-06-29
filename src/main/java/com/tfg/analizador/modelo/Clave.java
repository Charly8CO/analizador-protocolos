package com.tfg.analizador.modelo;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class Clave implements ElementoMensaje {
    private String identificador;
    private List<Agente> propietarios;

    public Clave(String identificador) {
        this.identificador = identificador;
        this.propietarios = new ArrayList<>();
    }

    @Override
    public String getIdentificador() {
        return identificador;
    }

    public void setIdentificador(String identificador) {
        this.identificador = identificador;
    }

    // Lista inmutable para proteger el encapsulamiento.
    public List<Agente> getPropietarios() {
        return Collections.unmodifiableList(propietarios);
    }

    public void anadirPropietario(Agente agente) {
        if (!this.propietarios.contains(agente)) {
            this.propietarios.add(agente);
        }
    }
}