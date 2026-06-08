package com.tfg.analizador.logica;

import java.util.ArrayList;
import java.util.List;

import com.tfg.analizador.modelo.Agente;
import com.tfg.analizador.modelo.Cifrado;
import com.tfg.analizador.modelo.Clave;
import com.tfg.analizador.modelo.ElementoMensaje;
import com.tfg.analizador.modelo.Nonce;

public class AnalizadorSintactico {

    //MÉTODO PRINCIPAL: PUNTO DE ENTRADA
    //Recibe el mensaje con texto bruto extraído por el analizador léxico.
     
    public List<ElementoMensaje> parsearContenido(String contenido, Agente actorCreador) {
        // Lista donde guardaremos los elementos del mensajes
        List<ElementoMensaje> elementos = new ArrayList<>();
        contenido = contenido.trim();

        if (contenido.isEmpty()) return elementos;

        // Dividimos el texto guiándonos por comas,
        // pero no podemos usar un split normal ya que este inutilizaría los bloques cifrados.
        //llamamos en su lugar a separarTokens

        List<String> tokens = separarTokens(contenido);

        // Comprobamos el tipo de cada una de las partes extraidas
        for (String token : tokens) {
            elementos.add(parsearElemento(token, actorCreador));
        }

        // Devolvemos el árbol
        return elementos;
    }

    //Este método comprueba si el objeto es un nodo hoja o un compuesto
    private ElementoMensaje parsearElemento(String token, Agente actorCreador) {
        token = token.trim();

        //Para bloques compuestos
        if (token.startsWith("{") && token.contains("}")) {
            
            int indexCierre = token.lastIndexOf("}");
            
            // Extraemos lo que hay entre las llaves. 
            String contenidoCifrado = token.substring(1, indexCierre); 
            
            // Leemos la clave que cifra el bloque
            String idClave = token.substring(indexCierre + 1).trim();  

            Clave clave = new Clave(idClave);
            Cifrado cifrado = new Cifrado(clave);

            // Recursivo
            List<ElementoMensaje> elementosInternos = parsearContenido(contenidoCifrado, actorCreador);

            for (ElementoMensaje e : elementosInternos) {
                cifrado.anadirElemento(e);
            }
            
            // Devolvemos el bloque cifrado
            return cifrado;
        }

        // Detectar Nonce y TimeStamps, empiezan por N o por T
        if (token.startsWith("N_") || (token.startsWith("N") && token.length() > 1) || token.startsWith("Time") || token.startsWith("T_")) {
            return new Nonce(token, actorCreador);
        }

        // Detectar clave, empiezan pro K
        if (token.startsWith("K_") || token.startsWith("K") && token.length() > 1) {
            return new Clave(token);
        }

        // El resto son agentes
        return new Agente(token);
    }

    // Lee el string pro comas pero si estan entre {} las deja pasar
    private List<String> separarTokens(String texto) {
        List<String> tokens = new ArrayList<>();
        int nivelLlaves = 0; 
        StringBuilder tokenActual = new StringBuilder(); 

        // Leemos el texto letra por letra
        for (char c : texto.toCharArray()) {

            if (c == '{') nivelLlaves++;
            if (c == '}') nivelLlaves--;

            // Si vemos una coma, separamos solo en caso de que no esté entre corchetes (es decir nivelLlave = 0)
            if (c == ',' && nivelLlaves == 0) {
                tokens.add(tokenActual.toString());
                tokenActual.setLength(0);
            } else {
                //seguimos guardando cada letra en el buffer para los demás casos
                tokenActual.append(c);
            }
        }
        
        if (tokenActual.length() > 0) {
            tokens.add(tokenActual.toString());
        }
        
        return tokens;
    }
}