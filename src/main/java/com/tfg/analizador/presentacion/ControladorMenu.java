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
}