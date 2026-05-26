package com.tfg.analizador.presentacion;

import com.tfg.analizador.logica.GestorSesion;
import com.tfg.analizador.util.GestorDialogos;
import com.tfg.analizador.util.GestorVistas;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;

public class ControladorMenu {

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