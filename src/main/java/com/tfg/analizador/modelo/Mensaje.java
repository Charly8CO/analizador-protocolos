package com.tfg.analizador.modelo;

public class Mensaje {
    private int numeroLinea;
    private Agente emisor;
    private Agente receptor;
    private String textoPlano;
    private String textoCifrado;

    public Mensaje(int numeroLinea, Agente emisor, Agente receptor, String textoPlano) {
        this.numeroLinea = numeroLinea;
        this.emisor = emisor;
        this.receptor = receptor;
        this.textoPlano = textoPlano;
    }

    public Agente getEmisor() { return emisor; }
    public void setEmisor(Agente emisor) { this.emisor = emisor; }

    public Agente getReceptor() { return receptor; }
    public void setReceptor(Agente receptor) { this.receptor = receptor; }

    public int getNumeroLinea() { return numeroLinea; }
    public void setNumeroLinea(int numeroLinea) { this.numeroLinea = numeroLinea; }

    public String getTextoPlano() { return textoPlano; }
    public void setTextoPlano(String textoPlano) { this.textoPlano = textoPlano; }

    public String getTextoCifrado() { return textoCifrado; }
    public void setTextoCifrado(String textoCifrado) { this.textoCifrado = textoCifrado; }
}