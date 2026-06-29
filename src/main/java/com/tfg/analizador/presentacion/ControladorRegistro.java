package com.tfg.analizador.presentacion;

import com.tfg.analizador.logica.GestorUsuarios;
import com.tfg.analizador.util.GestorVistas;
import com.tfg.analizador.util.ServicioEmail;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.VBox;

/**
 * Controlador para la gestión del registro de nuevos usuarios.
 * Implementa un flujo de dos pasos: (1) Formulario y (2) Verificación SMTP.
 */
public class ControladorRegistro {

    @FXML
    private VBox cajaFormulario;
    @FXML
    private TextField txtEmail;
    @FXML
    private PasswordField txtPass;
    @FXML
    private PasswordField txtConfirmarPass;
    @FXML
    private Button btnRegistrar;

    @FXML
    private VBox cajaVerificacion;
    @FXML
    private TextField txtCodigo;
    @FXML
    private Button btnVerificar;

    @FXML
    private Label lblError;

    // Variables temporales para mantener el estado del usuario en proceso de
    // registro
    private String codigoGeneradoTemp;
    private String emailPendienteTemp;
    private String passPendienteTemp;

    /**
     * Valida el formulario de registro y dispara el envío del código de
     * verificación.
     */
    @FXML
    public void handleRegistrarAction(ActionEvent event) {
        limpiarEstilosMensaje();

        String email = txtEmail.getText().trim();
        String pass = txtPass.getText();
        String passConf = txtConfirmarPass.getText();

        if (email.isEmpty() || pass.isEmpty() || passConf.isEmpty()) {
            mostrarError("Todos los campos son obligatorios");
            return;
        }

        String regexEmail = "^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$";
        if (!email.matches(regexEmail)) {
            mostrarError("El formato de email es incorrecto");
            return;
        }

        if (!pass.equals(passConf)) {
            mostrarError("Las contraseñas no coinciden");
            return;
        }

        // Bloqueamos la interfaz para evitar interacciones concurrentes durante la
        // espera del servidor SMTP
        btnRegistrar.setDisable(true);
        btnRegistrar.setText("Enviando correo, espera...");
        txtEmail.setDisable(true);
        txtPass.setDisable(true);
        txtConfirmarPass.setDisable(true);
        mostrarExito("Conectando con el servidor de correo...");

        codigoGeneradoTemp = ServicioEmail.generarCodigo();
        emailPendienteTemp = email;
        passPendienteTemp = pass;

        // Ejecución en segundo plano para no congelar el Hilo Principal (UI Thread)
        new Thread(() -> {
            try {
                ServicioEmail.enviarCodigoVerificacion(emailPendienteTemp, codigoGeneradoTemp);

                // Volvemos al Hilo Principal para realizar cambios en la vista
                javafx.application.Platform.runLater(() -> {
                    cambiarAVistaVerificacion();
                    mostrarExito("Se ha enviado un código a tu correo.");
                    // Restauramos campos por si el usuario vuelve atrás
                    btnRegistrar.setDisable(false);
                    btnRegistrar.setText("Registrarse");
                    txtEmail.setDisable(false);
                    txtPass.setDisable(false);
                    txtConfirmarPass.setDisable(false);
                });

            } catch (Exception e) {
                javafx.application.Platform.runLater(() -> {
                    mostrarError("Error SMTP: " + e.getMessage());
                    btnRegistrar.setDisable(false);
                    btnRegistrar.setText("Registrarse");
                    txtEmail.setDisable(false);
                    txtPass.setDisable(false);
                    txtConfirmarPass.setDisable(false);
                });
            }
        }).start();
    }

    /**
     * Valida el código introducido y, de ser correcto, registra al usuario en la
     * base de datos.
     */
    @FXML
    public void handleVerificarAction(ActionEvent event) {
        limpiarEstilosMensaje();
        String codigoIntroducido = txtCodigo.getText().trim();

        if (codigoIntroducido.equals(codigoGeneradoTemp)) {
            try {
                GestorUsuarios logicaUsuarios = new GestorUsuarios();
                logicaUsuarios.registrarNuevoUsuario(emailPendienteTemp, passPendienteTemp);

                // Visualización de éxito
                mostrarExito("¡Verificación completada! Cuenta creada con éxito.");

                // Ocultamos la caja de texto donde se escribió el código
                txtCodigo.setVisible(false);
                txtCodigo.setManaged(false);

                // Transformamos el botón existente en una pasarela al Login
                btnVerificar.setText("Ir a Iniciar Sesión");
                btnVerificar.setStyle("-fx-background-color: #2980B9; -fx-text-fill: white; -fx-font-weight: bold;");

                // Sobrescribimos su acción para que al pulsarlo te lleve al Login
                btnVerificar.setOnAction(e -> GestorVistas.irALogin());

                // Ocultamos el último elemento del VBox (el enlace de "Cancelar")
                int ultimoIndice = cajaVerificacion.getChildren().size() - 1;
                if (ultimoIndice >= 0) {
                    cajaVerificacion.getChildren().get(ultimoIndice).setVisible(false);
                    cajaVerificacion.getChildren().get(ultimoIndice).setManaged(false);
                }

            } catch (Exception e) {
                mostrarError(e.getMessage());
            }
        } else {
            mostrarError("El código es incorrecto.");
        }
    }

    @FXML
    public void handleCancelarVerificacion(MouseEvent event) {
        cajaVerificacion.setVisible(false);
        cajaVerificacion.setManaged(false);
        cajaFormulario.setVisible(true);
        cajaFormulario.setManaged(true);
        txtCodigo.clear();
        limpiarEstilosMensaje();
    }

    @FXML
    public void handleVolverLogin(MouseEvent event) {
        GestorVistas.irALogin();
    }

    private void mostrarError(String mensaje) {
        lblError.getStyleClass().remove("mensaje-exito");
        if (!lblError.getStyleClass().contains("mensaje-error"))
            lblError.getStyleClass().add("mensaje-error");
        lblError.setText(mensaje);
    }

    private void mostrarExito(String mensaje) {
        lblError.getStyleClass().remove("mensaje-error");
        if (!lblError.getStyleClass().contains("mensaje-exito"))
            lblError.getStyleClass().add("mensaje-exito");
        lblError.setText(mensaje);
    }

    private void limpiarEstilosMensaje() {
        lblError.setText("");
        lblError.getStyleClass().removeAll("mensaje-exito", "mensaje-error");
    }

    private void cambiarAVistaVerificacion() {
        cajaFormulario.setVisible(false);
        cajaFormulario.setManaged(false);
        cajaVerificacion.setVisible(true);
        cajaVerificacion.setManaged(true);
    }
}