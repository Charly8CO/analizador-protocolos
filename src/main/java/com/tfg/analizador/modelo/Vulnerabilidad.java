package com.tfg.analizador.modelo;

public class Vulnerabilidad {

	private String tipoAtaque;
	private int lineaAfectada;
	private String descripcion;

	public String getTipoAtaque() { 
		return tipoAtaque; 
	}
    public void setTipoAtaque(String tipoAtaque) { 
		this.tipoAtaque = tipoAtaque; 
	}
	
    public int getLineaAfectada() { 
		return lineaAfectada; 
	}
    public void setLineaAfectada(int lineaAfectada) { 
		this.lineaAfectada = lineaAfectada; 
	}

    public String getDescripcion() { 
		return descripcion; 
	}
    public void setDescripcion(String descripcion) { 
		this.descripcion = descripcion; 
	}

}