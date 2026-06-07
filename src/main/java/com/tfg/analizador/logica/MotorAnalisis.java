package com.tfg.analizador.logica;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.tfg.analizador.modelo.Cifrado;
import com.tfg.analizador.modelo.Clave;
import com.tfg.analizador.modelo.ElementoMensaje;
import com.tfg.analizador.modelo.Mensaje;
import com.tfg.analizador.modelo.Nonce;
import com.tfg.analizador.modelo.Protocolo;
import com.tfg.analizador.modelo.Vulnerabilidad;

public class MotorAnalisis {

    public List<Vulnerabilidad> evaluarFrescura(Protocolo p) {
        List<Vulnerabilidad> vulnerabilidades = new ArrayList<>();
        
        // Map para guardar <Identificador del Nonce, Nombre del Creador Original>
        Map<String, String> creadoresNonces = new HashMap<>();

        for (Mensaje m : p.getMensajes()) {
            List<Nonce> noncesEnMensaje = new ArrayList<>();

            // Extraemos todos los Nonces presentes en el mensaje
            for (ElementoMensaje elemento : m.getComponentes()) {
                extraerNoncesRecursivo(elemento, noncesEnMensaje);
            }

            // Evaluamos la propiedad de frescura (Freshness)
            for (Nonce n : noncesEnMensaje) {
                if (!creadoresNonces.containsKey(n.getIdentificador())) {
                    // Es la primera vez que vemos el Nonce. El emisor actual es su creador legítimo.
                    creadoresNonces.put(n.getIdentificador(), m.getEmisor().getNombre());
                } else {
                    // El Nonce ya existe. ¿Lo está reenviando otro agente o lo reutiliza el creador?
                    String creadorOriginal = creadoresNonces.get(n.getIdentificador());
                    
                    // Si el creador original vuelve a inyectar el MISMO nonce como si fuera nuevo
                    // en un paso posterior, viola la regla de "Number Used ONCE"
                    if (m.getEmisor().getNombre().equals(creadorOriginal)) {
                        Vulnerabilidad vuln = new Vulnerabilidad(
                            "Fallo de Frescura (Reutilización de Nonce)", 
                            m.getNumeroLinea(), 
                            "El agente " + creadorOriginal + " ha reutilizado el identificador " + n.getIdentificador() + " que ya había generado previamente. Esto compromete la frescura al violar la regla de un solo uso."
                        );
                        vulnerabilidades.add(vuln);
                        p.registrarVulnerabilidad(vuln);
                    }
                }
            }
        }
        return vulnerabilidades;
    }

    private void extraerNoncesRecursivo(ElementoMensaje elemento, List<Nonce> recolector) {
        if (elemento instanceof Nonce nonce) {
            recolector.add(nonce);
        } else if (elemento instanceof Cifrado bloqueCifrado) {
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
            // Usamos el método recursivo para sacar los nonces
            for (ElementoMensaje elemento : m.getComponentes()) {
                extraerNoncesRecursivo(elemento, noncesEnMensaje);
            }

            for (Nonce n : noncesEnMensaje) {
                boolean esRespuesta = false;
                
                // Comprobamos si el nonce actual está respondiendo a un desafío pendiente
                for (Desafio d : desafiosActivos) {
                    if (d.idNonce.equals(n.getIdentificador())) {
                        
                        //Si el creador del nonce lo recibe de vuelta, el desafío está superado.
                        if (m.getReceptor().getNombre().equals(d.emisorOriginal)) {
                            d.respondido = true;
                            esRespuesta = true;
                        }
                    }
                }

                if (!esRespuesta) {
                    boolean yaExiste = desafiosActivos.stream()
                        .anyMatch(d -> d.idNonce.equals(n.getIdentificador()));
                    
                    if (!yaExiste) {
                        desafiosActivos.add(new Desafio(
                            n.getIdentificador(), m.getEmisor().getNombre(), 
                            m.getReceptor().getNombre(), m.getNumeroLinea()
                        ));
                    }
                }
            }
        }

        // Si la lista está vacía, es que no hay ni un solo Nonce en todo el protocolo y por tanto no hay desafio-respuesta
        if (desafiosActivos.isEmpty()) {
            Vulnerabilidad advertencia = new Vulnerabilidad(
                "Advertencia Estructural (Falta de Desafío-Respuesta)", 0,
                "El protocolo no implementa ningún mecanismo de desafío-respuesta (no se han detectado Nonces). Esto lo hace altamente susceptible a ataques de repetición estáticos."
            );
            vulnerabilidades.add(advertencia);
            p.registrarVulnerabilidad(advertencia);
        } else {
             // Cuando se encuentran, comprobamos cuáles no fueron respondidos
            for (Desafio d : desafiosActivos) {
                if (!d.respondido) {
                    Vulnerabilidad vuln = new Vulnerabilidad(
                        "Fallo de Desafío-Respuesta", d.lineaDesafio,
                        "El agente " + d.emisorOriginal + " envió el nonce " + d.idNonce + " a " + d.receptorEsperado + ", pero nunca recibió una respuesta válida de vuelta."
                    );
                    vulnerabilidades.add(vuln);
                    p.registrarVulnerabilidad(vuln);
                }
            }
        }
        return vulnerabilidades;
    }

    public List<Vulnerabilidad> evaluarClavesYSuplantacion(Protocolo p) {
        List<Vulnerabilidad> vulnerabilidades = new ArrayList<>();
        
        // Llavero de claves dinámicas para cada agente 
        Map<String, Set<String>> conocimientosClaves = new HashMap<>();

        class TareaDescifrado {
            String agenteReceptor, idClaveNecesaria;
            int linea;
            boolean resuelta = false;
            TareaDescifrado(String ag, String cl, int l) {
                this.agenteReceptor = ag; this.idClaveNecesaria = cl; this.linea = l;
            }
        }
        
        List<TareaDescifrado> pendientes = new ArrayList<>();

        for (Mensaje m : p.getMensajes()) {
            String emisor = m.getEmisor().getNombre();
            String receptor = m.getReceptor().getNombre();
            
            // Inicializamos llaveros en blanco si no existían
            conocimientosClaves.putIfAbsent(emisor, new HashSet<>());
            conocimientosClaves.putIfAbsent(receptor, new HashSet<>());
            
            List<Cifrado> cifradosEnMensaje = new ArrayList<>();
            for (ElementoMensaje e : m.getComponentes()) {
                extraerCifradosRecursivo(e, cifradosEnMensaje);
            }
            
            for (Cifrado c : cifradosEnMensaje) {
                String idClaveSello = c.getClaveSello().getIdentificador();
                // Si emisor es "Alice", la clave debe contener "alice" (ej. K_alice_bob) comprobamos para el emisor
                boolean emisorConoceDeBase = emisor.equalsIgnoreCase("KDC") || emisor.equalsIgnoreCase("S") ||
                                             idClaveSello.toLowerCase().contains(emisor.toLowerCase());
                
                boolean emisorLaAdquirio = conocimientosClaves.get(emisor).contains(idClaveSello);
                
                // Si el emisor manda un cifrado con una clave que no tiene, es Spoofing
                if (!emisorConoceDeBase && !emisorLaAdquirio) {
                    Vulnerabilidad vuln = new Vulnerabilidad(
                        "Suplantación de Identidad (Spoofing)", m.getNumeroLinea(),
                        "El agente " + emisor + " envía un bloque cifrado con " + idClaveSello + " sin conocer la clave. Está suplantando la identidad del creador legítimo o reenviando un paquete robado."
                    );
                    vulnerabilidades.add(vuln);
                    p.registrarVulnerabilidad(vuln);
                }
                
                // Comprobamos para el receptor
                boolean receptorConoceDeBase = receptor.equalsIgnoreCase("KDC") || receptor.equalsIgnoreCase("S") ||
                                               idClaveSello.toLowerCase().contains(receptor.toLowerCase());
                                               
                boolean receptorLaAdquirio = conocimientosClaves.get(receptor).contains(idClaveSello);
                
                // Si el receptor no la conoce y no la adquirió, se crea tarea pendiente
                if (!receptorConoceDeBase && !receptorLaAdquirio) {
                    pendientes.add(new TareaDescifrado(receptor, idClaveSello, m.getNumeroLinea()));
                }
            }
            
            // Actualizamos la dinámica de llaveros buscando claves enviadas como datos
            List<Clave> clavesAdquiridas = new ArrayList<>();
            for (ElementoMensaje e : m.getComponentes()) {
                extraerClavesRecursivo(e, clavesAdquiridas);
            }
            
            for (Clave cl : clavesAdquiridas) {
                String idClaveAcabadaDeRecibir = cl.getIdentificador();
                // El receptor añade la clave a su memoria
                conocimientosClaves.get(receptor).add(idClaveAcabadaDeRecibir);
                
                // Si esto resuelve un mensaje que no podía leer antes, saldamos la deuda
                for (TareaDescifrado t : pendientes) {
                    if (t.agenteReceptor.equals(receptor) && t.idClaveNecesaria.equals(idClaveAcabadaDeRecibir)) {
                        t.resuelta = true; 
                    }
                }
            }
        }

        // Auditoría final de lectura
        for (TareaDescifrado t : pendientes) {
            if (!t.resuelta) {
                Vulnerabilidad vuln = new Vulnerabilidad(
                    "Fallo de Accesibilidad (Clave Inaccesible)", t.linea,
                    "El agente " + t.agenteReceptor + " recibió un bloque cifrado con " + t.idClaveNecesaria + ", pero no la posee ni le fue distribuida en toda la sesión. Es incapaz de leerlo."
                );
                vulnerabilidades.add(vuln);
                p.registrarVulnerabilidad(vuln);
            }
        }

        return vulnerabilidades;
    }

    private void extraerCifradosRecursivo(ElementoMensaje elemento, List<Cifrado> recolector) {
        if (elemento instanceof Cifrado c) {
            recolector.add(c);
            for (ElementoMensaje hijo : c.getContenido()) {
                extraerCifradosRecursivo(hijo, recolector); 
            }
        }
    }

    private void extraerClavesRecursivo(ElementoMensaje elemento, List<Clave> recolector) {
        if (elemento instanceof Clave clave) {
            recolector.add(clave);
        } else if (elemento instanceof Cifrado cifrado) {
            for (ElementoMensaje hijo : cifrado.getContenido()) {
                extraerClavesRecursivo(hijo, recolector); 
            }
        }
    }

    public boolean analizarEsSeguro(Protocolo p) {
        evaluarFrescura(p);
        evaluarDesafioRespuesta(p);
        evaluarClavesYSuplantacion(p); 
        
        return p.isSeguro();
    }
}