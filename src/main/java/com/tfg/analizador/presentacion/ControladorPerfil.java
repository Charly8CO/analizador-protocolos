package com.tfg.analizador.presentacion;

import org.mindrot.jbcrypt.BCrypt; // Importación necesaria si usas BCrypt

import com.tfg.analizador.logica.GestorSesion;
import com.tfg.analizador.modelo.Usuario;
import com.tfg.analizador.persistencia.GestorBBDD;
import com.tfg.analizador.util.GestorDialogos;
import com.tfg.analizador.util.GestorVistas;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;

public class ControladorPerfil {

    @FXML
    private Label lblUsuarioActual;

    @FXML
    private PasswordField txtPassActual;

    @FXML
    private PasswordField txtPassNueva;

    @FXML
    private PasswordField txtPassRepetir;

    private Usuario usuarioActual;
    private GestorBBDD gestorBD;

    @FXML
    public void initialize() {
        usuarioActual = GestorSesion.getInstancia().getUsuarioActivo();
        gestorBD = new GestorBBDD();

        if (usuarioActual != null) {
            lblUsuarioActual.setText("Usuario actual: " + usuarioActual.getNombreUsuario());
        }
    }

    @FXML
    void handleVolver(ActionEvent event) {
        GestorVistas.irADashB();
    }

    @FXML
    void handleCancelarPassword(ActionEvent event) {
        txtPassActual.clear();
        txtPassNueva.clear();
        txtPassRepetir.clear();
    }

    @FXML
    void handleCambiarPassword(ActionEvent event) {
        String actual = txtPassActual.getText();
        String nueva = txtPassNueva.getText();
        String repetir = txtPassRepetir.getText();

        if (actual.isEmpty() || nueva.isEmpty() || repetir.isEmpty()) {
            GestorDialogos.mostrarConfirmacionEstandar("Campos incompletos", "Faltan datos", "Por favor, rellena todos los campos de contraseña.", "Aceptar");
            return;
        }

        if (!nueva.equals(repetir)) {
            GestorDialogos.mostrarConfirmacionEstandar("Error", "No coinciden", "La nueva contraseña y su repetición no coinciden.", "Aceptar");
            return;
        }

        // Verificamos si la contraseña actual es correcta comparándola con el Hash de la BBDD
        if (!BCrypt.checkpw(actual, usuarioActual.getHashPass())) {
            GestorDialogos.mostrarConfirmacionEstandar("Error de Seguridad", "Contraseña incorrecta", "La contraseña actual introducida no es válida.", "Aceptar");
            return;
        }

        // Hasheamos la nueva contraseña y actualizamos
        String nuevoHash = BCrypt.hashpw(nueva, BCrypt.gensalt());
        if (gestorBD.actualizarPassword(usuarioActual.getIdUsuario(), nuevoHash)) {
            usuarioActual.setHashPass(nuevoHash); // Actualizamos memoria local
            GestorDialogos.mostrarConfirmacionEstandar("Éxito", "Contraseña cambiada", "Tu contraseña ha sido actualizada correctamente.", "Aceptar");
            handleCancelarPassword(null); // Limpiamos campos
        } else {
            GestorDialogos.mostrarConfirmacionEstandar("Error", "Fallo en la base de datos", "No se ha podido actualizar la contraseña.", "Aceptar");
        }
    }

    @FXML
    void handleCerrarSesion(ActionEvent event) {
        boolean confirmado = GestorDialogos.mostrarConfirmacionEstandar(
            "Cerrar Sesión",
            "Saliendo de la cuenta",
            "¿Estás seguro de que deseas cerrar tu sesión?",
            "Cerrar sesión"
        );

        if (confirmado) {
            GestorSesion.getInstancia().cerrarSesion();
            GestorVistas.irALogin();
        }
    }

    @FXML
    void handleBorrarCuenta(ActionEvent event) {
        // Utilizamos tu método destructivo en rojo
        boolean confirmado = GestorDialogos.mostrarAdvertenciaDestructiva(
            "ESTA ACCIÓN ES IRREVERSIBLE.\n\nSe eliminará de la base de datos tu usuario, todo el historial de protocolos analizados y las vulnerabilidades detectadas.\n\n(Los archivos físicos .prot en tu ordenador NO se borrarán).\n\n¿Estás absolutamente seguro?",
            "Borrar Cuenta Definitivamente"
        );

        if (confirmado) {
            if (gestorBD.eliminarUsuario(usuarioActual.getIdUsuario())) {
                GestorDialogos.mostrarConfirmacionEstandar("Cuenta Eliminada", "Lamentamos verte marchar", "Todos tus datos han sido borrados de la base de datos con éxito.", "Entendido");
                GestorSesion.getInstancia().cerrarSesion();
                GestorVistas.irALogin();
            } else {
                GestorDialogos.mostrarConfirmacionEstandar("Error crítico", "Fallo al borrar cuenta", "Hubo un problema interno y la cuenta no ha sido eliminada.", "Aceptar");
            }
        }
    }
}