package com.tfg.analizador.modelo;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class Protocolo {
    private int idProtocolo;
    private String nombreProtocolo;
    private Date fechaAnalisis;
    private boolean seguro;
    private String rutaArchivo; 
    
    // Contenedores de datos
    private List<Mensaje> mensajes;
    private List<Agente> agentes;
    private List<Vulnerabilidad> vulnerabilidades;

    public Protocolo(String nombreProtocolo) {
        this.nombreProtocolo = nombreProtocolo;
        this.fechaAnalisis = new Date();
        this.seguro = true;
        this.mensajes = new ArrayList<>();
        this.agentes = new ArrayList<>();
        this.vulnerabilidades = new ArrayList<>();
    }

    public void anadirLinea(Mensaje m) {
        this.mensajes.add(m);
    }

    public void anadirAgente(Agente a) {
        // Gracias a que programamos el equals(), esto no añadirá duplicados
        if (!this.agentes.contains(a)) {
            this.agentes.add(a);
        }
    }

    public void registrarVulnerabilidad(Vulnerabilidad v) {
        this.vulnerabilidades.add(v);
        this.seguro = false; // Al registrar la primera vulnerabilidad, deja de ser seguro
    }

    // Getters
    public int getIdProtocolo() { return idProtocolo; }
    public String getNombreProtocolo() { return nombreProtocolo; }
    public Date getFechaAnalisis() { return fechaAnalisis; }
    public boolean isSeguro() { return seguro; }
    public String getRutaArchivo() { return rutaArchivo; } // NUEVO
    public List<Mensaje> getMensajes() { return mensajes; }
    public List<Agente> getAgentes() { return agentes; }
    public List<Vulnerabilidad> getVulnerabilidades() { return vulnerabilidades; }

    // Setters
    public void setIdProtocolo(int idProtocolo) { this.idProtocolo = idProtocolo; }
    public void setNombreProtocolo(String nombreProtocolo) { this.nombreProtocolo = nombreProtocolo; }
    public void setFechaAnalisis(Date fechaAnalisis) { this.fechaAnalisis = fechaAnalisis; }
    public void setSeguro(boolean seguro) { this.seguro = seguro; }
    public void setRutaArchivo(String rutaArchivo) { this.rutaArchivo = rutaArchivo; } // NUEVO
}