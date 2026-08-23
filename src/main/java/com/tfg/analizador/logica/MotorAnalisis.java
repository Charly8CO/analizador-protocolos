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
import com.tfg.analizador.modelo.TipoVulnerabilidad;

public class MotorAnalisis {

    // Conjunto centralizado de entidades confiables.
    // Solo se reconocen "KDC" y "Trent" como servidores de confianza.
    // Esto evita falsos negativos con nombres de agente que contengan 's' o 't'.
    private static final Set<String> SERVIDORES_CONFIABLES = Set.of("KDC", "Trent");

    // Método auxiliar para comprobar si un agente es un servidor de confianza
    private boolean esServidorConfiable(String nombre) {
        return SERVIDORES_CONFIABLES.stream().anyMatch(s -> s.equalsIgnoreCase(nombre));
    }

    // Evalua la distribución de claves de sesión para evitar Ataques de repetición.
    public void evaluarFrescuraDeClaves(Protocolo p, List<Vulnerabilidad> vulnerabilidades) {
        // Diccionario para rastrear qué agente originó cada Nonce: <Identificador,
        // NombreCreador>
        Map<String, String> creadoresNonces = new HashMap<>();

        for (Mensaje m : p.getMensajes()) {
            String receptor = m.getReceptor().getNombre();
            String emisor = m.getEmisor().getNombre();

            // Registrar los creadores de los nuevos nonces
            List<Nonce> noncesEnMensaje = new ArrayList<>();
            for (ElementoMensaje e : m.getComponentes())
                extraerNoncesRecursivo(e, noncesEnMensaje);

            for (Nonce n : noncesEnMensaje) {
                String base = getBaseNonce(n.getIdentificador());
                creadoresNonces.putIfAbsent(base, emisor);
            }

            // Una vez memorizados los nonces, si el receptor es un servidor de confianza,
            // detenemos la auditoría de este mensaje porque los servidores no sufren Replay
            // Attacks.
            if (esServidorConfiable(receptor)) {
                continue;
            }

            // Auditar los tickets/cifrados que recibe el receptor
            List<Cifrado> cifrados = new ArrayList<>();
            for (ElementoMensaje e : m.getComponentes())
                extraerCifradosRecursivo(e, cifrados);

            for (Cifrado c : cifrados) {
                String claveSello = c.getClaveSello().getIdentificador();
                boolean receptorPuedeLeer = claveSello.toLowerCase().contains(receptor.toLowerCase());

                if (receptorPuedeLeer) {
                    List<Clave> clavesDentro = new ArrayList<>();
                    for (ElementoMensaje hijo : c.getContenido())
                        extraerClavesRecursivo(hijo, clavesDentro);

                    for (Clave k : clavesDentro) {
                        // Verificamos si se le está distribuyendo una clave de sesión (Ej: K_AB,
                        // descartando su propia clave maestra)
                        if (k.getIdentificador().toLowerCase().contains("k")
                                && !k.getIdentificador().equalsIgnoreCase(claveSello)) {

                            boolean tieneFrescura = false;
                            List<Nonce> noncesDentro = new ArrayList<>();
                            for (ElementoMensaje hijo : c.getContenido())
                                extraerNoncesRecursivo(hijo, noncesDentro);

                            // Búsqueda interna: Comprobamos si el ticket cerrado incluye una garantía de
                            // frescura
                            for (Nonce n : noncesDentro) {
                                String base = getBaseNonce(n.getIdentificador());
                                if (base.startsWith("Time") || base.startsWith("T_"))
                                    tieneFrescura = true;
                                if (receptor.equals(creadoresNonces.get(base)))
                                    tieneFrescura = true;
                            }

                            // Si el ticket no es fresco por dentro, miramos si en el mismo mensaje viaja
                            // otro bloque
                            // cifrado con esta clave que sí contenga la prueba de vida en paralelo.
                            if (!tieneFrescura) {
                                for (Cifrado otroCifrado : cifrados) {
                                    if (otroCifrado.getClaveSello().getIdentificador().equals(k.getIdentificador())) {
                                        List<Nonce> noncesAcompanantes = new ArrayList<>();
                                        for (ElementoMensaje hijo : otroCifrado.getContenido())
                                            extraerNoncesRecursivo(hijo, noncesAcompanantes);

                                        for (Nonce nAcomp : noncesAcompanantes) {
                                            String base = getBaseNonce(nAcomp.getIdentificador());
                                            if (base.startsWith("Time") || base.startsWith("T_"))
                                                tieneFrescura = true;
                                            if (receptor.equals(creadoresNonces.get(base)))
                                                tieneFrescura = true;
                                        }
                                    }
                                }
                            }

                            // Si tras ambas búsquedas no hay frescura, es vulnerable a reinyección.
                            if (!tieneFrescura) {
                                Vulnerabilidad vuln = new Vulnerabilidad(
                                        TipoVulnerabilidad.FALTA_FRESCURA.getDescripcion(), m.getNumeroLinea(),
                                        "El agente " + receptor + " recibe la clave de sesión " + k.getIdentificador()
                                                + " sin garantías de frescura en el mensaje. Un atacante podría reinyectar información de una sesión antigua.");
                                registrarVulnUnica(vulnerabilidades, p, vuln, m.getNumeroLinea());
                            }
                        }
                    }
                }
            }
        }
    }

    // Detecta ataques de espejo (Reflexión) y defectos de tipo (Type Flaws) (un
    // tipo de ataques similar a los de repetición).

    public void evaluarRiesgoReflexion(Protocolo p, List<Vulnerabilidad> vulnerabilidades) {
        // Clase interna para llevar un registro del formato exacto de los bloques que
        // emite cada agente
        class RegistroCifrado {
            String clave;
            String nonce;
            int numElementos;
            int posicion; // Rastreo de aridad e índice posicional

            RegistroCifrado(String c, String n, int num, int pos) {
                clave = c;
                nonce = n;
                numElementos = num;
                posicion = pos;
            }
        }

        // Memoria de los criptogramas que emite cada agente
        Map<String, List<RegistroCifrado>> emitidos = new HashMap<>();

        for (Mensaje m : p.getMensajes()) {
            String emisor = m.getEmisor().getNombre();
            String receptor = m.getReceptor().getNombre();

            List<Cifrado> cifrados = new ArrayList<>();
            for (ElementoMensaje e : m.getComponentes())
                extraerCifradosRecursivo(e, cifrados);

            for (Cifrado c : cifrados) {
                String clave = c.getClaveSello().getIdentificador();
                int numElementosCifrado = c.getContenido().size();

                // Si el receptor no puede leer la clave, solo actúa de cartero, no hay riesgo
                // de reflexión.
                boolean receptorPuedeLeer = esServidorConfiable(receptor)
                        || clave.toLowerCase().contains(receptor.toLowerCase());

                List<Nonce> nonces = new ArrayList<>();
                for (ElementoMensaje e : c.getContenido())
                    extraerNoncesRecursivo(e, nonces);

                for (Nonce n : nonces) {
                    // Operaciones como N-1 rompen la reflexión matemática, por lo que las ignoramos
                    if (!tieneOperacion(n.getIdentificador())) {
                        String baseNonce = getBaseNonce(n.getIdentificador());

                        // Buscamos en qué posición exacta del cifrado viaja el nonce
                        int posicionActual = obtenerPosicionNonce(c, baseNonce);

                        // Registramos lo que el emisor saca a la red guardando longitud y posición
                        // exacta
                        emitidos.computeIfAbsent(emisor, k -> new ArrayList<>())
                                .add(new RegistroCifrado(clave, baseNonce, numElementosCifrado, posicionActual));

                        // Evaluamos si el receptor actual es víctima de su propio reflejo
                        if (receptorPuedeLeer) {
                            List<RegistroCifrado> previos = emitidos.getOrDefault(receptor, new ArrayList<>());
                            for (RegistroCifrado prev : previos) {
                                if (prev.clave.equals(clave) && prev.nonce.equals(baseNonce)) {
                                    // Para que un ataque de reflexión / Type Flaw funcione, el bloque reflejado
                                    // debe tener la misma o mayor longitud,
                                    // y el Nonce debe estar en la misma en ambos bloques.
                                    if (numElementosCifrado <= prev.numElementos && posicionActual == prev.posicion) {
                                        Vulnerabilidad vuln = new Vulnerabilidad(
                                                TipoVulnerabilidad.REFLEXION.getDescripcion(), m.getNumeroLinea(),
                                                "El agente " + receptor + " espera un bloque (" + clave
                                                        + ") con su nonce intacto en la posición " + posicionActual
                                                        + ". Un atacante podría devolver (reflejar) este mismo bloque al emisor original haciéndose pasar por el receptor legítimo, explotando un defecto de tipo (Type Flaw).");
                                        registrarVulnUnica(vulnerabilidades, p, vuln, m.getNumeroLinea());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Evaluación de desafío respuesta
    public void evaluarDesafioRespuesta(Protocolo p, List<Vulnerabilidad> vulnerabilidades) {
        class Desafio {
            String idNonce;
            String emisorOriginal;
            boolean respondido = false;
            int lineaDesafio;

            Desafio(String id, String emisor, int linea) {
                this.idNonce = id;
                this.emisorOriginal = emisor;
                this.lineaDesafio = linea;
            }
        }

        List<Desafio> desafiosActivos = new ArrayList<>();
        boolean usaTimestamps = false;

        // Construimos el mapa de conocimientos globales para verificar que las
        // respuestas usan claves fiables
        Map<String, Set<String>> conocimientosGlobales = construirMapaConocimientos(p);

        for (Mensaje m : p.getMensajes()) {
            String receptorActual = m.getReceptor().getNombre();
            String emisorActual = m.getEmisor().getNombre();

            List<Nonce> noncesEnMensaje = new ArrayList<>();
            for (ElementoMensaje elemento : m.getComponentes())
                extraerNoncesRecursivo(elemento, noncesEnMensaje);

            for (Nonce n : noncesEnMensaje) {
                String idCompleto = n.getIdentificador();
                String baseNonce = getBaseNonce(idCompleto);

                // Las marcas de tiempo no requieren respuesta interactiva, actúan como
                // mitigadores globales.
                if (baseNonce.startsWith("Time") || baseNonce.startsWith("T_")) {
                    usaTimestamps = true;
                    continue;
                }

                boolean esRespuesta = false;
                for (Desafio d : desafiosActivos) {
                    if (d.idNonce.equals(baseNonce)) {

                        // El desafío solo se supera si el creador recibe el nonce de vuelta,
                        // y además viene cifrado o alterado algorítmicamente.
                        if (receptorActual.equals(d.emisorOriginal)) {
                            boolean estaMutado = tieneOperacion(idCompleto);
                            String claveEnvolvente = obtenerClaveEnvolvente(m.getComponentes(), baseNonce);

                            // Validamos que el criptograma de respuesta esté envuelto con una clave segura
                            // que el retador conozca
                            boolean esClaveConfiable = false;
                            if (!claveEnvolvente.equals("PLANO")) {
                                boolean retadorConoceDeBase = esServidorConfiable(d.emisorOriginal) ||
                                        claveEnvolvente.toLowerCase().contains(d.emisorOriginal.toLowerCase());

                                Set<String> conocimientosRetador = conocimientosGlobales.getOrDefault(d.emisorOriginal,
                                        new HashSet<>());
                                boolean retadorLaAdquirio = conocimientosRetador.contains(claveEnvolvente);

                                esClaveConfiable = retadorConoceDeBase || retadorLaAdquirio;
                            }

                            if (estaMutado || esClaveConfiable) {
                                d.respondido = true;
                                esRespuesta = true;
                            }
                        }
                    }
                }

                // Si no se identificó como una respuesta a un desafío previo, lo registramos
                // como un nuevo desafío al aire
                if (!esRespuesta) {
                    boolean yaExiste = desafiosActivos.stream().anyMatch(d -> d.idNonce.equals(baseNonce));
                    if (!yaExiste) {
                        desafiosActivos.add(new Desafio(baseNonce, emisorActual, m.getNumeroLinea()));
                    }
                }
            }
        }

        // Si el protocolo carece de control de estado se advierte estructuralmente.
        if (desafiosActivos.isEmpty() && !usaTimestamps) {
            Vulnerabilidad advertencia = new Vulnerabilidad(
                    TipoVulnerabilidad.ADVERTENCIA_DESAFIO_RESPUESTA.getDescripcion(), 0,
                    "El protocolo no implementa mecanismos de desafío-respuesta interactivos ni marcas de tiempo. Se recomienda incluir nonces (N_alice) o marcas de tiempo (Time) para garantizar la frescura de los mensajes.");
            registrarVulnUnica(vulnerabilidades, p, advertencia, 0);
        } else {
            for (Desafio d : desafiosActivos) {
                if (!d.respondido) {
                    Vulnerabilidad vuln = new Vulnerabilidad(
                            TipoVulnerabilidad.FALLO_DESAFIO_RESPUESTA.getDescripcion(), d.lineaDesafio,
                            "El agente " + d.emisorOriginal + " envió el nonce " + d.idNonce
                                    + " como desafío, pero nunca recibió una prueba criptográfica válida de vuelta confirmando su procesamiento.");
                    registrarVulnUnica(vulnerabilidades, p, vuln, d.lineaDesafio);
                }
            }
        }
    }

    // Comprueba si una clave de sesión distribuida es utilizada activamente por
    // ambas partes.
    public void evaluarAutenticacionMutua(Protocolo p, List<Vulnerabilidad> vulnerabilidades) {
        Set<String> clavesSesion = new HashSet<>();

        // Extraemos todas las claves de sesión distribuidas en el protocolo
        for (Mensaje m : p.getMensajes()) {
            List<Clave> claves = new ArrayList<>();
            for (ElementoMensaje e : m.getComponentes())
                extraerClavesRecursivo(e, claves);
            for (Clave k : claves) {
                String id = k.getIdentificador().toLowerCase();
                // Auditoría MF2: Filtrado robusto de claves de sesión.
                // Solo se excluyen claves que contengan nombres de servidores confiables
                // ("kdc", "trent").
                // Esto evita falsos negativos con agentes cuyos nombres contengan 's' o 't'.
                boolean involucraServidor = SERVIDORES_CONFIABLES.stream()
                        .anyMatch(srv -> id.contains(srv.toLowerCase()));
                if (id.contains("k") && !involucraServidor) {
                    clavesSesion.add(k.getIdentificador());
                }
            }
        }

        // Verificamos cuántos agentes distintos utilizan activamente cada clave de
        // sesión para cifrar
        for (String k : clavesSesion) {
            Set<String> usuariosQueCifran = new HashSet<>();
            for (Mensaje m : p.getMensajes()) {
                List<Cifrado> cifrados = new ArrayList<>();
                for (ElementoMensaje e : m.getComponentes())
                    extraerCifradosRecursivo(e, cifrados);
                for (Cifrado c : cifrados) {
                    if (c.getClaveSello().getIdentificador().equals(k)) {
                        usuariosQueCifran.add(m.getEmisor().getNombre());
                    }
                }
            }

            // Si la clave se distribuyó, pero solo un agente la utiliza, la otra parte
            // nunca confirmó la sesión.
            if (usuariosQueCifran.size() == 1) {
                String emisorUnico = usuariosQueCifran.iterator().next();
                Vulnerabilidad vuln = new Vulnerabilidad(
                        TipoVulnerabilidad.AUTENTICACION_UNILATERAL.getDescripcion(), p.getMensajes().size(),
                        "La clave de sesión " + k + " fue distribuida, pero solo " + emisorUnico
                                + " la utiliza activamente. Si es un protocolo interactivo, falla la Autenticación Mutua. Si es unidireccional (ej: Email/Asíncrono), es un comportamiento normal.");
                registrarVulnUnica(vulnerabilidades, p, vuln, p.getMensajes().size());
            }
        }
    }

    // Detecta suplantación (Spoofing) si un agente emite un cifrado sin conocer la
    // clave.
    // Detecta inaccesibilidad si un agente recibe un bloque cifrado y no tiene la
    // llave para abrirlo.

    public void evaluarClavesYSuplantacion(Protocolo p, List<Vulnerabilidad> vulnerabilidades) {
        // Mapas para almacenar lo que sabe cada agente y los tickets que simplemente
        // hace de "cartero"
        Map<String, Set<String>> conocimientosClaves = new HashMap<>();
        Map<String, Set<String>> ticketsParaReenviar = new HashMap<>();

        class TareaDescifrado {
            String agenteReceptor, idClaveNecesaria;
            int linea;
            boolean resuelta = false;

            TareaDescifrado(String ag, String cl, int l) {
                this.agenteReceptor = ag;
                this.idClaveNecesaria = cl;
                this.linea = l;
            }
        }

        List<TareaDescifrado> pendientes = new ArrayList<>();

        for (Mensaje m : p.getMensajes()) {
            String emisor = m.getEmisor().getNombre();
            String receptor = m.getReceptor().getNombre();

            conocimientosClaves.putIfAbsent(emisor, new HashSet<>());
            conocimientosClaves.putIfAbsent(receptor, new HashSet<>());
            ticketsParaReenviar.putIfAbsent(emisor, new HashSet<>());
            ticketsParaReenviar.putIfAbsent(receptor, new HashSet<>());

            List<Cifrado> cifradosEnMensaje = new ArrayList<>();
            for (ElementoMensaje e : m.getComponentes())
                extraerCifradosRecursivo(e, cifradosEnMensaje);

            for (Cifrado c : cifradosEnMensaje) {
                String idClaveSello = c.getClaveSello().getIdentificador();

                // Determinamos si el emisor tiene derecho lógico a usar esta clave
                boolean emisorConoceDeBase = esServidorConfiable(emisor) ||
                        idClaveSello.toLowerCase().contains(emisor.toLowerCase());
                boolean emisorLaAdquirio = conocimientosClaves.get(emisor).contains(idClaveSello);
                boolean esReenvioDeTicket = ticketsParaReenviar.get(emisor).contains(idClaveSello);

                // Si no la conoce de base, ni la adquirió, ni la está reenviando como cartero
                // opaco -> Spoofing
                if (!emisorConoceDeBase && !emisorLaAdquirio && !esReenvioDeTicket) {
                    Vulnerabilidad vuln = new Vulnerabilidad(
                            TipoVulnerabilidad.SPOOFING.getDescripcion(), m.getNumeroLinea(),
                            "El agente " + emisor + " envía un bloque cifrado con " + idClaveSello
                                    + " sin poseer la clave simétrica. Está forjando un mensaje falso o utilizando una clave a la que no debería tener acceso.");
                    registrarVulnUnica(vulnerabilidades, p, vuln, m.getNumeroLinea());
                }
                // Comprueba la accesibilidad
                boolean receptorConoceDeBase = esServidorConfiable(receptor) ||
                        idClaveSello.toLowerCase().contains(receptor.toLowerCase());
                boolean receptorLaAdquirio = conocimientosClaves.get(receptor).contains(idClaveSello);

                if (!receptorConoceDeBase && !receptorLaAdquirio) {
                    // Si no puede abrirlo, se anota como tarea pendiente y se guarda como ticket
                    // opaco para reenvío
                    pendientes.add(new TareaDescifrado(receptor, idClaveSello, m.getNumeroLinea()));
                    ticketsParaReenviar.get(receptor).add(idClaveSello);
                } else {
                    // Si PUEDE abrirlo, y esto era un ticket de transporte, la deuda queda saldada
                    if (esReenvioDeTicket) {
                        for (TareaDescifrado t : pendientes) {
                            if (t.agenteReceptor.equals(emisor) && t.idClaveNecesaria.equals(idClaveSello))
                                t.resuelta = true;
                        }
                    }
                }
            }

            List<Clave> clavesNuevas = new ArrayList<>();
            for (ElementoMensaje e : m.getComponentes()) {
                // Solo adquiere conocimiento (interior de las llaves) si posee la clave para
                // descifrar el bloque
                adquirirConocimientoRecursivo(e, receptor, conocimientosClaves.get(receptor), clavesNuevas);
            }

            // Verificamos si alguna clave nueva resuelve un bloqueo pendiente anterior
            for (Clave cl : clavesNuevas) {
                for (TareaDescifrado t : pendientes) {
                    if (t.agenteReceptor.equals(receptor) && t.idClaveNecesaria.equals(cl.getIdentificador()))
                        t.resuelta = true;
                }
            }
        }

        // Si quedaron bloques cifrados que no pudieron abrirse ni enviarse a su
        // destino.
        for (TareaDescifrado t : pendientes) {
            if (!t.resuelta) {
                Vulnerabilidad vuln = new Vulnerabilidad(
                        TipoVulnerabilidad.FALLO_ACCESIBILIDAD.getDescripcion(), t.linea,
                        "El agente " + t.agenteReceptor + " recibió un bloque cifrado con " + t.idClaveNecesaria
                                + " pero carece de la clave simétrica para descifrar el bloque, lo que impide que el protocolo avance correctamente. Verifique que la clave de descifrado se distribuya antes de este mensaje.");
                registrarVulnUnica(vulnerabilidades, p, vuln, t.linea);
            }
        }
    }

    // Auditoría O1: Oportunidad de memoización identificada.
    // Cada método evaluarXxx recorre el AST de forma independiente. Para protocolos
    // muy grandes,
    // se podría optimizar extrayendo cifrados, nonces y claves en una única pasada
    // previa
    // y pasando los resultados cacheados a cada evaluador.
    // Orquestador principal que ejecuta secuencialmente todos los módulos de
    // auditoría.
    public boolean analizarEsSeguro(Protocolo p) {
        List<Vulnerabilidad> vulnerabilidades = new ArrayList<>();

        evaluarFrescuraDeClaves(p, vulnerabilidades);
        evaluarRiesgoReflexion(p, vulnerabilidades);
        evaluarDesafioRespuesta(p, vulnerabilidades);
        evaluarAutenticacionMutua(p, vulnerabilidades);
        evaluarClavesYSuplantacion(p, vulnerabilidades);

        return p.isSeguro();
    }

    // Extrae de forma aislada el conocimiento de claves que cada agente adquirirá a
    // lo largo del protocolo.
    // Muy útil para simulaciones de conocimiento previo (Dolev-Yao).
    private Map<String, Set<String>> construirMapaConocimientos(Protocolo p) {
        Map<String, Set<String>> conocimientosClaves = new HashMap<>();
        for (Mensaje m : p.getMensajes()) {
            String receptor = m.getReceptor().getNombre();
            conocimientosClaves.putIfAbsent(receptor, new HashSet<>());

            List<Clave> clavesNuevas = new ArrayList<>();
            for (ElementoMensaje e : m.getComponentes()) {
                adquirirConocimientoRecursivo(e, receptor, conocimientosClaves.get(receptor), clavesNuevas);
            }
        }
        return conocimientosClaves;
    }

    // Explora ciega y recursivamente un elemento extrayendo todas las estructuras
    // de cifrado anidadas.
    private void extraerCifradosRecursivo(ElementoMensaje elemento, List<Cifrado> recolector) {
        if (elemento instanceof Cifrado c) {
            recolector.add(c);
            for (ElementoMensaje hijo : c.getContenido())
                extraerCifradosRecursivo(hijo, recolector);
        }
    }

    // Verifica si un Nonce viaja protegido dentro de un bloque cifrado o circula en
    // texto plano.
    private String obtenerClaveEnvolvente(List<ElementoMensaje> componentes, String baseNonce) {
        for (ElementoMensaje e : componentes) {
            if (e instanceof Cifrado c) {
                List<Nonce> noncesAqui = new ArrayList<>();
                for (ElementoMensaje hijo : c.getContenido())
                    extraerNoncesRecursivo(hijo, noncesAqui);
                boolean loContiene = noncesAqui.stream()
                        .anyMatch(n -> getBaseNonce(n.getIdentificador()).equals(baseNonce));
                if (loContiene)
                    return c.getClaveSello().getIdentificador();
            }
        }
        return "PLANO";
    }

    // Extrae recursivamente todas las claves presentes en un elemento.
    private void extraerClavesRecursivo(ElementoMensaje elemento, List<Clave> recolector) {
        if (elemento instanceof Clave clave) {
            recolector.add(clave);
        } else if (elemento instanceof Cifrado cifrado) {
            for (ElementoMensaje hijo : cifrado.getContenido())
                extraerClavesRecursivo(hijo, recolector);
        }
    }

    // Extrae recursivamente todos los Nonces presentes en un elemento.
    private void extraerNoncesRecursivo(ElementoMensaje elemento, List<Nonce> recolector) {
        if (elemento instanceof Nonce nonce) {
            recolector.add(nonce);
        } else if (elemento instanceof Cifrado bloqueCifrado) {
            for (ElementoMensaje hijo : bloqueCifrado.getContenido())
                extraerNoncesRecursivo(hijo, recolector);
        }
    }

    // Comprueba si el identificador de un elemento contiene una mutación,
    // operación matemática (+, -) o aplicación de función F(N).
    private boolean tieneOperacion(String identificador) {
        return identificador.contains("+") || identificador.contains("-")
                || (identificador.contains("(") && identificador.contains(")"));
    }

    // Limpia operaciones aritméticas o funciones devolviendo la base de la variable.
    // Soporta N_A+1, N_A-1 y F(N_A), H(N_Bob), etc.
    private String getBaseNonce(String identificador) {
        // Si contiene paréntesis, extraemos el contenido interior: F(N_A) -> N_A
        if (identificador.contains("(") && identificador.contains(")")) {
            int abre = identificador.indexOf('(');
            int cierra = identificador.lastIndexOf(')');
            if (abre < cierra) {
                return identificador.substring(abre + 1, cierra).trim();
            }
        }
        // Limpieza clásica de operaciones aritméticas: N_A+1 -> N_A
        return identificador.split("[\\+\\-]", 2)[0].trim();
    }

    // Auditoría C1: Corregido bug de deduplicación.
    // Se añade la vulnerabilidad a la lista local para que el filtro funcione en
    // llamadas posteriores.
    private void registrarVulnUnica(List<Vulnerabilidad> lista, Protocolo p, Vulnerabilidad v, int linea) {
        boolean duplicada = lista.stream().anyMatch(existente -> existente.getLineaAfectada() == linea
                && existente.getTipoAtaque().equals(v.getTipoAtaque()));
        if (!duplicada) {
            lista.add(v);
            p.registrarVulnerabilidad(v);
        }
    }

    // Localiza el índice posicional exacto de un nonce dentro del array de un
    // bloque cifrado.
    private int obtenerPosicionNonce(Cifrado c, String baseNonce) {
        for (int i = 0; i < c.getContenido().size(); i++) {
            List<Nonce> noncesEnHijo = new ArrayList<>();
            extraerNoncesRecursivo(c.getContenido().get(i), noncesEnHijo);
            for (Nonce n : noncesEnHijo) {
                if (getBaseNonce(n.getIdentificador()).equals(baseNonce))
                    return i;
            }
        }
        return -1;
    }

    // Navega por el árbol de componentes del mensaje y solo extrae las claves si el
    // agente
    // demuestra poseer la llave que abre el cifrado envolvente
    private void adquirirConocimientoRecursivo(ElementoMensaje elemento, String agente, Set<String> conocimientos,
            List<Clave> recolector) {
        if (elemento instanceof Clave clave) {
            recolector.add(clave);
            conocimientos.add(clave.getIdentificador());
        } else if (elemento instanceof Cifrado cifrado) {
            String idSello = cifrado.getClaveSello().getIdentificador();
            boolean puedeAbrir = esServidorConfiable(agente) ||
                    idSello.toLowerCase().contains(agente.toLowerCase()) ||
                    conocimientos.contains(idSello);

            if (puedeAbrir) {
                for (ElementoMensaje hijo : cifrado.getContenido()) {
                    adquirirConocimientoRecursivo(hijo, agente, conocimientos, recolector);
                }
            }
        }
    }
}