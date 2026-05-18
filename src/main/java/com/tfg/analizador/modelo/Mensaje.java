package com.tfg.analizador.modelo;

public class Mensaje {

	private int numeroLinea;
	private String textoPlano;
	private String textoCifrado;

	public Agente getEmisor() {
		// TODO - implement Mensaje.getEmisor
		throw new UnsupportedOperationException();
	}

	public Agente getReceptor() {
		// TODO - implement Mensaje.getReceptor
		throw new UnsupportedOperationException();
	}

	public int getNumeroLinea() { 
		return numeroLinea; 
	}
    public void setNumeroLinea(int numeroLinea) { 
		this.numeroLinea = numeroLinea; 
	}

    public String getTextoPlano() { 
		return textoPlano; 
	}
    public void setTextoPlano(String textoPlano) { 
		this.textoPlano = textoPlano;
	}

    public String getTextoCifrado() { 
		return textoCifrado; 
	}
    public void setTextoCifrado(String textoCifrado) { 
		this.textoCifrado = textoCifrado; 
	}

}