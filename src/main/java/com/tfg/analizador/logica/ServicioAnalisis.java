package com.tfg.analizador.logica;

import java.io.File;
import java.nio.file.Files;

import com.tfg.analizador.modelo.Protocolo;
import com.tfg.analizador.modelo.Usuario;
import com.tfg.analizador.persistencia.GestorBBDD;

public class ServicioAnalisis {
    
    public boolean validarSintaxisSolo(String textoPlano) throws Exception {
        AnalizadorLexico analizador = new AnalizadorLexico();
        return analizador.analizarSintaxis(textoPlano);
    }

    public Protocolo procesarNuevoProtocolo(String textoPlano) throws Exception {
        AnalizadorLexico analizador = new AnalizadorLexico();
        MotorAnalisis motor = new MotorAnalisis();
        
        // Compilación 
        Protocolo p = analizador.compilarProtocolo("Análisis_Actual", textoPlano);
        
        // Analizar
        motor.analizarEsSeguro(p);
        
        return p;
    }

    // Método integrador que orquesta todo el flujo (Analizar + Local condicional + BD adaptativo)
    public Protocolo procesarYGuardarProtocolo(String textoPlano, File archivo) throws Exception {
        AnalizadorLexico analizador = new AnalizadorLexico();
        MotorAnalisis motor = new MotorAnalisis();
        
        // Compilación usando el nombre real del archivo
        Protocolo p = analizador.compilarProtocolo(archivo.getName(), textoPlano);
        
        // Analizar (carga las vulnerabilidades en memoria dentro del objeto 'p')
        motor.analizarEsSeguro(p);
        
        Usuario usuarioActivo = GestorSesion.getInstancia().getUsuarioActivo();
        if (usuarioActivo == null) {
            throw new Exception("No hay un usuario activo en la sesión para guardar el historial.");
        }
        
        // Verificamos si ya existe el archivo en el historial SQLite.
        // Si no existe, procedemos al guardado local automático inicial.
        int idExistente = GestorBBDD.obtenerIdProtocoloPorNombre(usuarioActivo.getIdUsuario(), archivo.getName());
        boolean esPrimeraVez = (idExistente == -1);

        if (esPrimeraVez) {
            // Guardado en el disco local SOLO si es la primera vez (no está en la BD)
            Files.writeString(archivo.toPath(), textoPlano);
            System.out.println("[LOCAL] Guardado automático inicial creado en: " + archivo.getName());
        } else {
            // Se omite la escritura en disco duro si ya se encuentra registrado el elemento
            System.out.println("[LOCAL] El protocolo ya existe en el historial. Se salta la escritura física.");
        }

        // Registro completo en la base de datos
        GestorBBDD gestor = new GestorBBDD();
        boolean exito = gestor.guardarHistorial(usuarioActivo, p, archivo.getAbsolutePath());

        if (!exito) {
            throw new Exception("El archivo se analizó correctamente, pero falló la actualización del historial en SQLite.");
        }
        
        return p;
    }

    public void guardarProtocolo(File archivo, String contenido) throws Exception {
        // Guardado en local
        Files.writeString(archivo.toPath(), contenido);

        // Registro en la base de datos 
        // Obtenemos el usuario de la sesión actual
        Usuario usuarioActivo = GestorSesion.getInstancia().getUsuarioActivo();
        
        if (usuarioActivo != null) {
            // Usamos la actualización inteligente en vez de inserción duplicada
            boolean exito = GestorBBDD.registrarGuardadoManual(
                usuarioActivo.getIdUsuario(), 
                archivo.getName(), 
                archivo.getAbsolutePath()
            );

            if (!exito) {
                throw new Exception("El archivo se guardó en el disco local, pero hubo un error al registrarlo en el historial de la base de datos.");
            } else {
                System.out.println("Guardado registrado en SQLite: " + archivo.getName() + " para el usuario " + usuarioActivo.getNombreUsuario());
            }
        }
    }
}