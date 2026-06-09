package com.tfg.analizador.presentacion;

import java.io.File;

import com.tfg.analizador.logica.GestorSesion;
import com.tfg.analizador.persistencia.GestorArchivos;
import com.tfg.analizador.util.GestorDialogos;
import com.tfg.analizador.util.GestorVistas;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.stage.FileChooser;

public class ControladorMenu {

    private ControladorAnalisis controladorAnalisis;

    // Método para inyectar la dependencia desde el GestorVistas
    public void setControladorAnalisis(ControladorAnalisis controladorAnalisis) {
        this.controladorAnalisis = controladorAnalisis;
    }

    @FXML
    void handleCerrarSesion(ActionEvent event) {
        
        boolean confirmado = GestorDialogos.mostrarConfirmacionEstandar(
            "Cerrar Sesión",
            "Estás a punto de salir del panel",
            "¿Estás seguro de que deseas cerrar sesión? Asegúrate de haber guardado tus análisis.",
            "Cerrar sesión"
        );

        if (confirmado) {
            GestorSesion.getInstancia().cerrarSesion();
            GestorVistas.irALogin();
        }
    }

    @FXML
    void handleVolverPrincipal(ActionEvent event){
        if (GestorVistas.getPantallaActual() == GestorVistas.TipoPantalla.ANALIZADOR) {

            boolean confirmado = GestorDialogos.mostrarConfirmacionEstandar(
                "Volver al DashBoard",
                "Estás a punto de salir del panel",
                "¿Estás seguro de que quieres volver al DahsBoard? Asegúrate de haber guardado tus análisis.",
                "Okay"
            );

            if (confirmado) {
                GestorVistas.irADashB();
            }
        }else{
            GestorVistas.irADashB();
        }
    }

    @FXML
    void handleImportarProtocolo(ActionEvent event) {
        // Comprobamos si estamos en la pestaña de análisis para lanzar la advertencia de que se perderán los datos actuales no guardados.
        if (GestorVistas.getPantallaActual() == GestorVistas.TipoPantalla.ANALIZADOR) {
            boolean confirmado = GestorDialogos.mostrarConfirmacionEstandar(
                "Advertencia",
                "Análisis en progreso",
                "Si importas un protocolo ahora, perderás el análisis actual no guardado en pantalla. ¿Deseas continuar?",
                "Continuar y sobrescribir"
            );

            // Si el usuario cancela, detenemos la importación
            if (!confirmado) {
                return; 
            }
        }

        FileChooser selector = new FileChooser();
        selector.setTitle("Importar Protocolo");
        selector.getExtensionFilters().add(new FileChooser.ExtensionFilter("Archivos de Protocolo (*.prot)", "*.prot"));
        
        File archivo = selector.showOpenDialog(null);

        if (archivo != null) {
            try {
                // Leemos el archivo con nuestro GestorArchivos
                GestorArchivos gestor = new GestorArchivos();
                String contenido = gestor.importarTextoArchivo(archivo);
                
                // Usamos el GestorVistas para cargar el analizador y le pasamos el archivo para que lo inyecte, sin importar en qué vista estemos.
                GestorVistas.irAAnalizadorConArchivo(contenido, archivo);
                
                GestorDialogos.mostrarConfirmacionEstandar("Éxito", "Importación completada", "El protocolo se ha cargado correctamente.", "Aceptar");
                
            } catch (Exception e) {
                GestorDialogos.mostrarConfirmacionEstandar("Error", "No se pudo importar", e.getMessage(), "Aceptar");
            }
        }
    }

    @FXML
    void handleMostrarGuia(ActionEvent event) {
        GestorVistas.mostrarGuiaUsuario();
    }

    @FXML
    void handleVerPerfil(ActionEvent event) {
        GestorVistas.irAPerfil();
    }

    @FXML
    void handleNuevoProtocolo(ActionEvent event) {
        // Comprobamos si el usuario ya está dentro del editor
        if (GestorVistas.getPantallaActual() == GestorVistas.TipoPantalla.ANALIZADOR) {

            boolean confirmado = GestorDialogos.mostrarConfirmacionEstandar(
                "Advertencia",
                "Análisis en progreso",
                "Si creas un nuevo protocolo perderás el análisis actual no guardado en pantalla. ¿Deseas continuar?",
                "Continuar y borrar"
            );

            // Si acepta recargamos 
            if (confirmado) {
                GestorVistas.irAAnalizador();
            }
            
        } else {
            // Si viene desde otra pestaña que no sea el analizador no pregunta
            GestorVistas.irAAnalizador();
        }
    }
}