package com.tfg.analizador.util;

import java.util.Properties;
import java.util.Random;
import javax.mail.*;
import javax.mail.internet.*;

public class ServicioEmail {

    // Cambia esto por un correo tuyo de pruebas y su respectiva Contraseña de Aplicación
    // AnalizadorTFG
    private static final String REMITENTE = "gestorregistroautonomo@gmail.com";
    private static final String PASSWORD = "ewoj hxpm mtuf nrjj";//"ProyectoTFG25-26";

    // Genera un código numérico aleatorio de 6 dígitos.
    public static String generarCodigo() {
        Random rnd = new Random();
        int numero = rnd.nextInt(999999);
        return String.format("%06d", numero);
    }

    // Envía un correo electrónico mediante SMTP con el código de verificación.
    public static void enviarCodigoVerificacion(String destinatario, String codigo) throws Exception {
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", "smtp.gmail.com"); // Servidor SMTP de Gmail
        props.put("mail.smtp.port", "587"); // Puerto TLS

        Session session = Session.getInstance(props, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(REMITENTE, PASSWORD);
            }
        });

        Message message = new MimeMessage(session);
        message.setFrom(new InternetAddress(REMITENTE));
        message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(destinatario));
        message.setSubject("Código de Verificación - Analizador de Protocolos");
        message.setText("Hola,\n\nTu código de verificación de 6 dígitos para finalizar tu registro es: " 
                        + codigo + "\n\nPor favor, introduce este código en la aplicación.\n\nSaludos.");

        Transport.send(message);
    }
}