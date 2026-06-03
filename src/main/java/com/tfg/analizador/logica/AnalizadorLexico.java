package com.tfg.analizador.logica;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.tfg.analizador.modelo.Agente;
import com.tfg.analizador.modelo.ElementoMensaje;
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

    // Mantenemos este método independiente por si el Controlador visual lo necesita 
    // para hacer una validación rápida sin instanciar todo el árbol
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

    // Transforma el texto bruto en el AST completo para el Motor de Análisis.
    public Protocolo compilarProtocolo(String nombreProtocolo, String textoPlano) {
        if (textoPlano == null || textoPlano.trim().isEmpty()) {
            throw new IllegalArgumentException("El protocolo no puede estar vacío.");
        }

        Protocolo protocolo = new Protocolo(nombreProtocolo);
        String[] lineas = textoPlano.split("\\r?\\n");
        int numeroLinea = 1;

        // Instanciamos nuestro nuevo analizador sintáctico (AST)
        AnalizadorSintactico parser = new AnalizadorSintactico();

        // Extraemos los datos de cada linea en un único recorrido
        for (String linea : lineas) {
            if (linea.trim().isEmpty()) {
                numeroLinea++;
                continue;
            }

            Matcher matcher = patternLinea.matcher(linea);
            
            // Validamos y extraemos en el mismo paso
            if (!matcher.matches()) {
                throw new IllegalArgumentException("Error de sintaxis en la línea " + numeroLinea + ": Estructura incorrecta. Use el formato 'Emisor -> Receptor : Mensaje'.");
            }

            // Sacamos los trozos exactos detectados por los paréntesis del RegEx
            String strEmisor = matcher.group(1);
            String strReceptor = matcher.group(2);
            String contenido = matcher.group(3).trim();

            // Creamos las instancias de los agentes
            Agente emisor = new Agente(strEmisor);
            Agente receptor = new Agente(strReceptor);

            // Los guardamos en el protocolo (el equals evitará duplicados)
            protocolo.anadirAgente(emisor);
            protocolo.anadirAgente(receptor);

            // Ensamblamos la raíz del mensaje
            Mensaje mensaje = new Mensaje(numeroLinea, emisor, receptor, contenido);
            
            // Le pasamos el texto bruto del contenido y el emisor (por si genera nonces)
            List<ElementoMensaje> componentes = parser.parsearContenido(contenido, emisor);
            for(ElementoMensaje e : componentes) {
                mensaje.anadirComponente(e);
            }

            protocolo.anadirLinea(mensaje);
            numeroLinea++;
        }

        return protocolo;
    }
}