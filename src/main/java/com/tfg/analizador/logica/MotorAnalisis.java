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
        List<Vulnerabilidad> vulnerabilidades = new ArrayList<>();
        
        // Clase interna auxiliar para rastrear el estado de cada desafío en la sesión
        class Desafio {
            String idNonce;
            String emisorOriginal;
            String receptorEsperado;
            boolean respondido = false;
            int lineaDesafio;

            Desafio(String id, String emisor, String receptor, int linea) {
                this.idNonce = id;
                this.emisorOriginal = emisor;
                this.receptorEsperado = receptor;
                this.lineaDesafio = linea;
            }
        }
        
        List<Desafio> desafiosActivos = new ArrayList<>();

        for (Mensaje m : p.getMensajes()) {
            List<Nonce> noncesEnMensaje = new ArrayList<>();
            // Usamos el método recursivo que ya creamos para sacar los nonces
            for (ElementoMensaje elemento : m.getComponentes()) {
                extraerNoncesRecursivo(elemento, noncesEnMensaje);
            }

            for (Nonce n : noncesEnMensaje) {
                boolean esRespuesta = false;
                
                // Comprobamos si el nonce actual está respondiendo a un desafío pendiente
                for (Desafio d : desafiosActivos) {
                    if (d.idNonce.equals(n.getIdentificador())) {
                        // El que responde debe coincidir con el receptor del mensaje qeu enviaba el nonce
                        if (m.getEmisor().getNombre().equals(d.receptorEsperado) && 
                            m.getReceptor().getNombre().equals(d.emisorOriginal)) {
                            d.respondido = true;
                            esRespuesta = true;
                        }
                    }
                }

                // Si el nonce no es respuesta a nada, es un desafío nuevo que se lanza
                if (!esRespuesta) {

                    boolean yaExiste = desafiosActivos.stream()
                        .anyMatch(d -> d.idNonce.equals(n.getIdentificador()));
                    
                    if (!yaExiste) {
                        desafiosActivos.add(new Desafio(
                            n.getIdentificador(), 
                            m.getEmisor().getNombre(), 
                            m.getReceptor().getNombre(), 
                            m.getNumeroLinea()
                        ));
                    }
                }
            }
        }

        if (desafiosActivos.isEmpty()) {
            // Si la lista está vacía, es que no hay ni un solo Nonce en todo el protocolo
            Vulnerabilidad advertencia = new Vulnerabilidad(
                "Advertencia Estructural (Falta de Desafío-Respuesta)",
                0,
                "El protocolo no implementa ningún mecanismo de desafío-respuesta (no se han detectado Nonces). Esto lo hace altamente susceptible a ataques de repetición."
            );
            vulnerabilidades.add(advertencia);
            p.registrarVulnerabilidad(advertencia);
        } else {
            // Cuando se encuentran, comprobamos cuáles no fueron respondidos
            for (Desafio d : desafiosActivos) {
                if (!d.respondido) {
                    Vulnerabilidad vuln = new Vulnerabilidad(
                        "Fallo de Desafío-Respuesta",
                        d.lineaDesafio,
                        "El agente " + d.emisorOriginal + " envió el nonce " + d.idNonce + " a " + d.receptorEsperado + ", pero nunca recibió una respuesta válida de vuelta."
                    );
                    vulnerabilidades.add(vuln);
                    p.registrarVulnerabilidad(vuln);
                }
            }
        }
        return vulnerabilidades;
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