package com.tfg.analizador.modelo;

public class Nonce implements  ElementoMensaje{
    private String identificador;
    private Agente creador;
    private boolean esFresco;

    public Nonce(String identificador, Agente creador) {
        this.identificador = identificador;
        this.creador = creador;
        this.esFresco = true; 
    }

	@Override
    public String getIdentificador() { return identificador; }
    public void setIdentificador(String identificador) { this.identificador = identificador; }

    public Agente getCreador() { return creador; }
    public void setCreador(Agente creador) { this.creador = creador; }

    public boolean isFresco() { return esFresco; }
    public void setFresco(boolean esFresco) { this.esFresco = esFresco; }
}