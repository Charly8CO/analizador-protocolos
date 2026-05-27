package com.tfg.analizador.modelo;

import java.util.ArrayList;
import java.util.List;

public class Mensaje {
    private int numeroLinea;
    private Agente emisor;
    private Agente receptor;
    private String textoPlano;
    //antes era un string de texto cifrado pero al implementar elementosMensajes es mucho mejor usar una lista de estos
    private List<ElementoMensaje> componentes;

    public Mensaje(int numeroLinea, Agente emisor, Agente receptor, String textoPlano) {
        this.numeroLinea = numeroLinea;
        this.emisor = emisor;
        this.receptor = receptor;
        this.textoPlano = textoPlano;
        this.componentes = new ArrayList<>();
    }

    public Agente getEmisor() { return emisor; }
    public void setEmisor(Agente emisor) { this.emisor = emisor; }

    public Agente getReceptor() { return receptor; }
    public void setReceptor(Agente receptor) { this.receptor = receptor; }

    public int getNumeroLinea() { return numeroLinea; }
    public void setNumeroLinea(int numeroLinea) { this.numeroLinea = numeroLinea; }

    public String getTextoPlano() { return textoPlano; }
    public void setTextoPlano(String textoPlano) { this.textoPlano = textoPlano; }

    public List<ElementoMensaje> getComponentes() { return componentes; }
    
    public void anadirComponente(ElementoMensaje componente) { 
        this.componentes.add(componente); 
    }
}