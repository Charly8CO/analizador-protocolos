package com.tfg.analizador.logica;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.tfg.analizador.modelo.Cifrado;
import com.tfg.analizador.modelo.ElementoMensaje;
import com.tfg.analizador.modelo.Mensaje;
import com.tfg.analizador.modelo.Nonce;
import com.tfg.analizador.modelo.Protocolo;
import com.tfg.analizador.modelo.Vulnerabilidad;

public class MotorAnalisis {

    public List<Vulnerabilidad> evaluarFrescura(Protocolo p) {
        List<Vulnerabilidad> vulnerabilidades = new ArrayList<>();
        Set<String> noncesVistos = new HashSet<>();

        for (Mensaje m : p.getMensajes()) {
            List<Nonce> noncesEnMensaje = new ArrayList<>();

            // Extraemos todos los Nonces 
            for (ElementoMensaje elemento : m.getComponentes()) {
                extraerNoncesRecursivo(elemento, noncesEnMensaje);
            }

            // Evaluamos la frescura
            for (Nonce n : noncesEnMensaje) {

				// Si vemos un nonce por primera vez lo registramos
                if (!noncesVistos.contains(n.getIdentificador())) {
                    noncesVistos.add(n.getIdentificador());
                } else {
                    // Si un Nonce viaja en texto plano múltiples veces 
                    // sin estar dentro de un bloque cifrado, podría ser un ataque de repetición.
                    Vulnerabilidad vuln = new Vulnerabilidad(
                        "Fallo de Frescura (Posible Replay Attack)", 
                        m.getNumeroLinea(), 
                        "El identificador " + n.getIdentificador() + " ha sido reutilizado. Esto compromete la frescura del mensaje."
                    );
                    vulnerabilidades.add(vuln);
                    p.registrarVulnerabilidad(vuln);
                }
            }
        }
        return vulnerabilidades;
    }

    private void extraerNoncesRecursivo(ElementoMensaje elemento, List<Nonce> recolector) {
        // Si el elemento es un nodo hoja de tipo Nonce, lo guardamos
        if (elemento instanceof Nonce) {
            recolector.add((Nonce) elemento);
        } 
        // Si el elemento es un nodo compuesto (Cifrado), aplicamos recursividad
        else if (elemento instanceof Cifrado) {
            Cifrado bloqueCifrado = (Cifrado) elemento;
            for (ElementoMensaje hijo : bloqueCifrado.getContenido()) {
                extraerNoncesRecursivo(hijo, recolector);
            }
        }
    }

    public List<Vulnerabilidad> evaluarDesafioRespuesta(Protocolo p) {
        // TODO: Implementar lógica de desafío-respuesta
        return new ArrayList<>();
    }

    public List<Vulnerabilidad> evaluarSuplantaciOn(Protocolo p) {
        // TODO: Implementar lógica de suplantación
        return new ArrayList<>();
    }

    public boolean analizarEsSeguro(Protocolo p) {
        evaluarFrescura(p);
        evaluarDesafioRespuesta(p);
        evaluarSuplantaciOn(p);
        
        return p.isSeguro();
    }
}