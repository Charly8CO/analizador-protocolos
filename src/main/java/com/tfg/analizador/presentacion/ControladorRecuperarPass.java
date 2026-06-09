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
 * Controlador para la gestión de la recuperación de contraseñas.
 * Implementa un flujo de 3 fases: Solicitud, Verificación SMTP y Cambio de Contraseña.
 */
public class ControladorRecuperarPass {

    @FXML private Label lblError;
    @FXML private VBox cajaEmail;
    @FXML private TextField txtEmail;
    @FXML private Button btnEnviarCodigo;
    @FXML private VBox cajaVerificacion;
    @FXML private TextField txtCodigo;
    @FXML private Button btnVerificar;
    @FXML private VBox cajaNuevaPass;
    @FXML private PasswordField txtNuevaPass;
    @FXML private PasswordField txtConfirmarPass;
    @FXML private Button btnActualizar;

    private String codigoGeneradoTemp;
    private String emailValidadoTemp;

    // Verifica que el correo exista en la BBDD y envía el código por SMTP.
    @FXML
    public void handleEnviarCodigo(ActionEvent event) {
        limpiarEstilosMensaje();
        String email = txtEmail.getText().trim();

        if (email.isEmpty()) {
            mostrarError("Por favor, introduce tu correo electrónico.");
            return;
        }

        try {
            GestorUsuarios logicaUsuarios = new GestorUsuarios();
            if (!logicaUsuarios.existeUsuario(email)) {
                mostrarError("No se ha encontrado ninguna cuenta vinculada a este correo.");
                return;
            }

            // Bloqueamos la UI mientras conecta con SMTP
            btnEnviarCodigo.setDisable(true);
            btnEnviarCodigo.setText("Enviando...");
            txtEmail.setDisable(true);
            mostrarExito("Conectando con el servidor...");

            codigoGeneradoTemp = ServicioEmail.generarCodigo();
            emailValidadoTemp = email;

            // Hilo en segundo plano para el envío
            new Thread(() -> {
                try {
                    ServicioEmail.enviarCodigoVerificacion(emailValidadoTemp, codigoGeneradoTemp);
                    
                    javafx.application.Platform.runLater(() -> {
                        mostrarExito("Código enviado al correo. Revísalo (y Spam).");
                        
                        // Transición a la Fase 2
                        cajaEmail.setVisible(false);
                        cajaEmail.setManaged(false);
                        cajaVerificacion.setVisible(true);
                        cajaVerificacion.setManaged(true);
                    });

                } catch (Exception e) {
                    javafx.application.Platform.runLater(() -> {
                        mostrarError("Error SMTP: " + e.getMessage());
                        btnEnviarCodigo.setDisable(false);
                        btnEnviarCodigo.setText("Enviar código de seguridad");
                        txtEmail.setDisable(false);
                    });
                }
            }).start();

        } catch (Exception e) {
            mostrarError(e.getMessage());
        }
    }

    // Comprueba si el código numérico introducido es el correcto.
    @FXML
    public void handleVerificarCodigo(ActionEvent event) {
        limpiarEstilosMensaje();
        String codigoIntroducido = txtCodigo.getText().trim();

        if (codigoIntroducido.equals(codigoGeneradoTemp)) {
            mostrarExito("Código correcto. Ahora puedes establecer tu nueva contraseña.");
            
            // Transición a la Fase 3
            cajaVerificacion.setVisible(false);
            cajaVerificacion.setManaged(false);
            cajaNuevaPass.setVisible(true);
            cajaNuevaPass.setManaged(true);
        } else {
            mostrarError("El código introducido es incorrecto.");
        }
    }

    // Realiza la petición final de guardado de la nueva contraseña.
    @FXML
    public void handleActualizarPass(ActionEvent event) {
        limpiarEstilosMensaje();
        String pass1 = txtNuevaPass.getText();
        String pass2 = txtConfirmarPass.getText();

        if (pass1.isEmpty() || pass2.isEmpty()) {
            mostrarError("Todos los campos son obligatorios.");
            return;
        }

        if (!pass1.equals(pass2)) {
            mostrarError("Las contraseñas no coinciden.");
            return;
        }

        try {
            GestorUsuarios logicaUsuarios = new GestorUsuarios();
            logicaUsuarios.actualizarContrasena(emailValidadoTemp, pass1);

            mostrarExito("¡Contraseña actualizada con éxito!");
            
            // Ocultamos los campos y convertimos el botón en una salida al Login
            txtNuevaPass.setVisible(false); txtNuevaPass.setManaged(false);
            txtConfirmarPass.setVisible(false); txtConfirmarPass.setManaged(false);
            
            // Ocultamos las etiquetas de texto de la fase 3
            cajaNuevaPass.getChildren().get(0).setVisible(false); cajaNuevaPass.getChildren().get(0).setManaged(false);
            cajaNuevaPass.getChildren().get(2).setVisible(false); cajaNuevaPass.getChildren().get(2).setManaged(false);

            btnActualizar.setText("Ir a Iniciar Sesión");
            btnActualizar.setStyle("-fx-background-color: #27AE60; -fx-text-fill: white; -fx-font-weight: bold;");
            btnActualizar.setOnAction(e -> GestorVistas.irALogin());

        } catch (Exception e) {
            mostrarError(e.getMessage());
        }
    }

    @FXML
    public void handleCancelar(MouseEvent event) {
        // Restaura todo al estado inicial si se pulsa "Cancelar y volver"
        cajaVerificacion.setVisible(false); cajaVerificacion.setManaged(false);
        cajaNuevaPass.setVisible(false); cajaNuevaPass.setManaged(false);
        cajaEmail.setVisible(true); cajaEmail.setManaged(true);
        
        txtEmail.setDisable(false);
        btnEnviarCodigo.setDisable(false);
        btnEnviarCodigo.setText("Enviar código de seguridad");
        
        txtCodigo.clear();
        limpiarEstilosMensaje();
    }

    @FXML
    public void handleVolverLogin(MouseEvent event) {
        GestorVistas.irALogin();
    }

    private void mostrarError(String mensaje) {
        lblError.getStyleClass().remove("mensaje-exito");
        if (!lblError.getStyleClass().contains("mensaje-error")) lblError.getStyleClass().add("mensaje-error");
        lblError.setText(mensaje);
    }

    private void mostrarExito(String mensaje) {
        lblError.getStyleClass().remove("mensaje-error");
        if (!lblError.getStyleClass().contains("mensaje-exito")) lblError.getStyleClass().add("mensaje-exito");
        lblError.setText(mensaje);
    }

    private void limpiarEstilosMensaje() {
        lblError.setText("");
        lblError.getStyleClass().removeAll("mensaje-exito", "mensaje-error");
    }
}