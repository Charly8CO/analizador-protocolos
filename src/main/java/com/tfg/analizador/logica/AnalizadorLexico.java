package com.tfg.analizador.logica;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.tfg.analizador.modelo.Agente;
import com.tfg.analizador.modelo.Mensaje;
import com.tfg.analizador.modelo.Protocolo;

public class AnalizadorLexico {

    // Esta es la estructura que deberán tener las sentencias.
	// Busca un Emisor, una flecha (->), un Receptor, dos puntos (:) y el resto del texto
    private static final String PATRON_LINEA = "^\\s*([a-zA-Z0-9_]+)\\s*->\\s*([a-zA-Z0-9_]+)\\s*:\\s*(.+)$";
    private Pattern patternLinea;

    public AnalizadorLexico() {
        // Compilamos el patrón al construir el objeto para ganar rendimiento
        this.patternLinea = Pattern.compile(PATRON_LINEA);
    }

	//Validación de las reglas básicas
    public boolean analizarSintaxis(String texto) {
        if (texto == null || texto.trim().isEmpty()) return false;

        String[] lineas = texto.split("\\r?\\n");
        for (int i = 0; i < lineas.length; i++) {
            String linea = lineas[i];
            if (linea.trim().isEmpty()) continue; // Ignoramos líneas en blanco
            
            Matcher matcher = patternLinea.matcher(linea);
            if (!matcher.matches()) {
                throw new IllegalArgumentException("Error de sintaxis en la línea " + (i + 1) + ": Estructura incorrecta. Use el formato 'Emisor -> Receptor : Mensaje'.");
            }
        }
        return true;
    }

	// Transforma el texto bruto en objetos Java para el Motor de Análisis.
    public Protocolo compilarProtocolo(String nombreProtocolo, String textoPlano) {
        //Verificamos que no haya errores tipográficos primero
        analizarSintaxis(textoPlano);

        Protocolo protocolo = new Protocolo(nombreProtocolo);
        String[] lineas = textoPlano.split("\\r?\\n");
        int numeroLinea = 1;

        // Extraemos los datos de cada linea
        for (String linea : lineas) {
            if (linea.trim().isEmpty()) {
                numeroLinea++;
                continue;
            }

            Matcher matcher = patternLinea.matcher(linea);
            if (matcher.matches()) {
                // Sacamos los trozos exactos detectados por los paréntesis del RegEx
                String strEmisor = matcher.group(1);
                String strReceptor = matcher.group(2);
                String contenido = matcher.group(3).trim();

                // Creamos las instancias
                Agente emisor = new Agente(strEmisor);
                Agente receptor = new Agente(strReceptor);

                // Los guardamos en el protocolo (el equals que programamos antes evitará clonaciones)
                protocolo.anadirAgente(emisor);
                protocolo.anadirAgente(receptor);

                // Ensamblamos el mensaje
                Mensaje mensaje = new Mensaje(numeroLinea, emisor, receptor, contenido);
                protocolo.anadirLinea(mensaje);
            }
            numeroLinea++;
        }

        return protocolo;
    }
}