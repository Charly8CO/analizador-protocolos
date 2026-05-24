package com.tfg.analizador.util;

import java.util.Optional;

import javafx.scene.control.Alert;
import javafx.scene.control.ButtonBar;
import javafx.scene.control.ButtonType;
import javafx.scene.control.DialogPane;

public class GestorDialogos {

    /**
     * @param mensaje 
     * @param textoBotonRojo 
     * @return 
     */
    public static boolean mostrarAdvertenciaDestructiva(String mensaje, String textoBotonRojo) {
        
        Alert alerta = new Alert(Alert.AlertType.WARNING);
        alerta.setTitle("Advertencia");
        alerta.setHeaderText(null); 
        alerta.setContentText(mensaje);

        // Se crean los botones 
        ButtonType botonCancelar = new ButtonType("Cancelar", ButtonBar.ButtonData.CANCEL_CLOSE);
        ButtonType botonEliminar = new ButtonType(textoBotonRojo, ButtonBar.ButtonData.OK_DONE);

        alerta.getButtonTypes().setAll(botonCancelar, botonEliminar);

        // Obtener el panel base
        DialogPane dialogPane = alerta.getDialogPane();
        dialogPane.getStylesheets().add(GestorDialogos.class.getResource("/com/tfg/analizador/css/estilos.css").toExternalForm());
        
        // Le aplicamos su css al botón de eliminar
        javafx.scene.Node btnEliminarNode = dialogPane.lookupButton(botonEliminar);
        if (btnEliminarNode != null) {
            btnEliminarNode.getStyleClass().add("boton-peligro");
        }

        Optional<ButtonType> resultado = alerta.showAndWait();
        return resultado.isPresent() && resultado.get() == botonEliminar;
    }


    /**
     * Genera una ventana de confirmación estándar para acciones no destructivas.
     * @param titulo El título de la ventana.
     * @param cabecera El texto principal destacado.
     * @param mensaje El texto secundario explicativo.
     * @param textoBotonConfirmar El texto del botón de acción principal.
     * @return true si el usuario acepta, false si cancela.
     */
    public static boolean mostrarConfirmacionEstandar(String titulo, String cabecera, String mensaje, String textoBotonConfirmar) {
        
        Alert alerta = new Alert(Alert.AlertType.CONFIRMATION);
        alerta.setTitle(titulo);
        alerta.setHeaderText(cabecera);
        alerta.setContentText(mensaje);

        ButtonType botonCancelar = new ButtonType("Cancelar", ButtonBar.ButtonData.CANCEL_CLOSE);
        ButtonType botonConfirmar = new ButtonType(textoBotonConfirmar, ButtonBar.ButtonData.OK_DONE);

        alerta.getButtonTypes().setAll(botonCancelar, botonConfirmar);

        Optional<ButtonType> resultado = alerta.showAndWait();
        return resultado.isPresent() && resultado.get() == botonConfirmar;
    }
}