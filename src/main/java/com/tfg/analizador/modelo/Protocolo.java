package com.tfg.analizador.modelo;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class Protocolo {

	private int idProtocolo;
	private String nombreProtocolo;
	private Date fechaAnalisis;
	private boolean seguro;
	private List<Mensaje> mensajes = new ArrayList<>();

	/**
	 * 
	 * @param m
	 */
	public void anadirLinea(Mensaje m) {
		// TODO - implement Protocolo.anadirLinea
		throw new UnsupportedOperationException();
	}

	/**
	 * 
	 * @param a
	 */
	public void anadirAgente(Agente a) {
		// TODO - implement Protocolo.anadirAgente
		throw new UnsupportedOperationException();
	}

	/**
	 * 
	 * @param v
	 */
	public void registrarVulnerabilidad(Vulnerabilidad v) {
		// TODO - implement Protocolo.registrarVulnerabilidad
		throw new UnsupportedOperationException();
	}

}