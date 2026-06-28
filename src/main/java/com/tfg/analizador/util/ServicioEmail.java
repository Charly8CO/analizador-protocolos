package com.tfg.analizador.util;

import java.util.Properties;
import java.util.Random;
import javax.mail.*;
import javax.mail.internet.*;

public class ServicioEmail {

    // Genera un código numérico aleatorio de 6 dígitos.
    public static String generarCodigo() {
        Random rnd = new Random();
        int numero = rnd.nextInt(999999);
        return String.format("%06d", numero);
    }

    // Envía un correo electrónico mediante SMTP con el código de verificación.
    public static void enviarCodigoVerificacion(String destinatario, String codigo) throws Exception {
        // Lectura de credenciales desde el archivo externo config.properties
        GestorConfiguracion config = GestorConfiguracion.getInstancia();
        String remitente = config.getPropiedad("mail.remitente");
        String password = config.getPropiedad("mail.password");

        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", "smtp.gmail.com"); // Servidor SMTP de Gmail
        props.put("mail.smtp.port", "587"); // Puerto TLS

        Session session = Session.getInstance(props, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(remitente, password);
            }
        });

        Message message = new MimeMessage(session);
        message.setFrom(new InternetAddress(remitente));
        message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(destinatario));
        message.setSubject("Código de Verificación - Analizador de Protocolos");
        message.setText("Hola,\n\nTu código de verificación de 6 dígitos para finalizar tu registro es: " 
                        + codigo + "\n\nPor favor, introduce este código en la aplicación.\n\nSaludos.");

        Transport.send(message);
    }
}