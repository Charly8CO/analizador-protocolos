package com.tfg.analizador.logica;

import java.util.ArrayList;
import java.util.List;

import com.tfg.analizador.modelo.Agente;
import com.tfg.analizador.modelo.Cifrado;
import com.tfg.analizador.modelo.Clave;
import com.tfg.analizador.modelo.ElementoMensaje;
import com.tfg.analizador.modelo.Nonce;

public class AnalizadorSintactico {

    // Límite de profundidad para evitar StackOverflow con inputs malformados
    // establecido en
    // 20 niveles (lo que es más que suficiente para cualquier protocolo
    // criptográfico real).
    private static final int MAX_PROFUNDIDAD = 20;

    // Recibe el mensaje con texto bruto extraído por el analizador léxico.
    public List<ElementoMensaje> parsearContenido(String contenido, Agente actorCreador) {
        return parsearContenidoInterno(contenido, actorCreador, 0);
    }

    private List<ElementoMensaje> parsearContenidoInterno(String contenido, Agente actorCreador, int profundidad) {
        if (profundidad > MAX_PROFUNDIDAD) {
            throw new AnalizadorException(
                    "Error: Nivel de anidamiento criptográfico excesivo (>" + MAX_PROFUNDIDAD + "). "
                            + "Revise la estructura del protocolo.");
        }

        // Lista donde guardaremos los elementos del mensajes
        List<ElementoMensaje> elementos = new ArrayList<>();
        contenido = contenido.trim();

        if (contenido.isEmpty())
            return elementos;

        // Dividimos el texto guiándonos por comas,
        // pero no podemos usar un split normal ya que este inutilizaría los bloques
        // cifrados.
        // llamamos en su lugar a separarTokens

        List<String> tokens = separarTokens(contenido);

        // Comprobamos el tipo de cada una de las partes extraidas
        for (String token : tokens) {
            elementos.add(parsearElemento(token, actorCreador, profundidad));
        }

        // Devolvemos el árbol
        return elementos;
    }

    // Este método comprueba si el objeto es un nodo hoja o uno compuesto
    private ElementoMensaje parsearElemento(String token, Agente actorCreador, int profundidad) {
        token = token.trim();

        // Para bloques compuestos
        if (token.startsWith("{") && token.contains("}")) {

            int indexCierre = token.lastIndexOf("}");

            // Extraemos lo que hay entre las llaves.
            String contenidoCifrado = token.substring(1, indexCierre);

            // Leemos la clave que cifra el bloque
            String idClave = token.substring(indexCierre + 1).trim();

            Clave clave = new Clave(idClave);
            Cifrado cifrado = new Cifrado(clave);

            // Se incrementa la profundidad para controlar el límite de anidamiento
            List<ElementoMensaje> elementosInternos = parsearContenidoInterno(contenidoCifrado, actorCreador,
                    profundidad + 1);

            for (ElementoMensaje e : elementosInternos) {
                cifrado.anadirElemento(e);
            }

            // Devolvemos el bloque cifrado
            return cifrado;
        }

        // Detectar Nonce envuelto en función: F(N_A), H(N_Bob), G(T_Alice), etc.
        // Se clasifica como Nonce manteniendo el identificador completo (ej. "F(N_A)")
        // para que el motor lo reconozca como operación/mutación.
        if (token.contains("(") && token.contains(")")) {
            int abre = token.indexOf('(');
            int cierra = token.lastIndexOf(')');
            if (abre < cierra) {
                if (abre == 0) {
                    throw new AnalizadorException("Error de Sintaxis: Se han encontrado paréntesis sin nombre de función en '" + token + "'. Debe indicar una función delante, por ejemplo 'F" + token + "' o 'Hash" + token + "'.");
                }
                String interior = token.substring(abre + 1, cierra).trim();
                if (interior.startsWith("N_") || interior.startsWith("N") || interior.startsWith("T_") || interior.startsWith("Time")) {
                    return new Nonce(token, actorCreador);
                }
            }
        }

        // Detectar Nonce y TimeStamps, empiezan por N o por T
        if (token.startsWith("N_") || (token.startsWith("N") && token.length() > 1) || token.startsWith("Time")
                || token.startsWith("T_")) {
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

            if (c == '{')
                nivelLlaves++;
            if (c == '}')
                nivelLlaves--;

            // Si vemos una coma, separamos solo en caso de que no esté entre corchetes (es
            // decir nivelLlave = 0)
            if (c == ',' && nivelLlaves == 0) {
                tokens.add(tokenActual.toString());
                tokenActual.setLength(0);
            } else {
                // seguimos guardando cada letra en el buffer para los demás casos
                tokenActual.append(c);
            }
        }

        if (tokenActual.length() > 0) {
            tokens.add(tokenActual.toString());
        }

        return tokens;
    }
}