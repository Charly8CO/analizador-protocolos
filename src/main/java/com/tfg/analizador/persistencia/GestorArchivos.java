package com.tfg.analizador.persistencia;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.text.SimpleDateFormat;

import com.itextpdf.text.BaseColor;
import com.itextpdf.text.Document;
import com.itextpdf.text.Element;
import com.itextpdf.text.Font;
import com.itextpdf.text.FontFactory;
import com.itextpdf.text.Paragraph;
import com.itextpdf.text.Phrase;
import com.itextpdf.text.pdf.PdfPCell;
import com.itextpdf.text.pdf.PdfPTable;
import com.itextpdf.text.pdf.PdfWriter;

import com.tfg.analizador.modelo.Protocolo;
import com.tfg.analizador.modelo.Usuario;
import com.tfg.analizador.modelo.Vulnerabilidad;

public class GestorArchivos {

    /**
     * Exporta un protocolo a un archivo de texto plano.
     */
    public boolean exportarArchivo(Protocolo p, String ruta) {
        // Delegado al ServicioAnalisis.guardarProtocolo en tu arquitectura actual
        throw new UnsupportedOperationException("Utiliza ServicioAnalisis.guardarProtocolo para esta acción.");
    }

    /**
     * MODIFICADO: Lee el contenido de un archivo físico y lo devuelve como texto plano
     * para que pueda ser insertado en el editor CodeArea.
     */
    public String importarTextoArchivo(File archivo) throws Exception {
        if (archivo == null || !archivo.exists()) {
            throw new Exception("El archivo seleccionado no existe o no es válido.");
        }
        return Files.readString(archivo.toPath());
    }

    /**
     * NUEVO: Genera un informe PDF profesional con los resultados del análisis.
     * @param p El protocolo analizado.
     * @param rutaDestino La ruta donde se guardará el PDF.
     * @param textoOriginal El texto plano del editor para incluirlo en el informe.
     * @param u El usuario que ha realizado el análisis.
     */
    public void generarInformePDF(Protocolo p, String rutaDestino, String textoOriginal, Usuario u) throws Exception {
        Document document = new Document();
        PdfWriter.getInstance(document, new FileOutputStream(rutaDestino));
        
        document.open();
        
        // Fuentes
        Font fontTitulo = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 18, BaseColor.BLACK);
        Font fontSubtitulo = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 14, BaseColor.DARK_GRAY);
        Font fontNormal = FontFactory.getFont(FontFactory.HELVETICA, 12, BaseColor.BLACK);
        Font fontCodigo = FontFactory.getFont(FontFactory.COURIER, 11, BaseColor.BLACK);

        // Cabecera del Documento
        Paragraph titulo = new Paragraph("Informe de Seguridad de Protocolo Criptográfico", fontTitulo);
        titulo.setAlignment(Element.ALIGN_CENTER);
        document.add(titulo);
        document.add(new Paragraph("\n")); // Espaciado

        // Metadatos
        document.add(new Paragraph("Analista (Usuario): " + (u != null ? u.getNombreUsuario() : "Invitado"), fontNormal));
        document.add(new Paragraph("Nombre del Protocolo: " + p.getNombreProtocolo(), fontNormal));
        SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
        document.add(new Paragraph("Fecha de Análisis: " + sdf.format(p.getFechaAnalisis()), fontNormal));
        
        String estadoSeguridad = p.isSeguro() ? "SEGURO (No se detectaron brechas lógicas)" : "INSEGURO (Vulnerabilidades detectadas)";
        Paragraph pEstado = new Paragraph("Estado Global: " + estadoSeguridad, fontSubtitulo);
        pEstado.setSpacingBefore(10);
        document.add(pEstado);
        document.add(new Paragraph("\n"));

        // Código del Protocolo
        document.add(new Paragraph("Código del Protocolo Analizado:", fontSubtitulo));
        Paragraph pCodigo = new Paragraph(textoOriginal, fontCodigo);
        pCodigo.setSpacingBefore(5);
        pCodigo.setSpacingAfter(15);
        document.add(pCodigo);

        // Tabla de Vulnerabilidades 
        if (!p.isSeguro() && !p.getVulnerabilidades().isEmpty()) {
            document.add(new Paragraph("Vulnerabilidades Detectadas:", fontSubtitulo));
            document.add(new Paragraph("\n"));

            PdfPTable table = new PdfPTable(3);
            table.setWidthPercentage(100);
            table.setWidths(new float[]{2f, 1f, 4f}); // Proporciones de las columnas

            // Cabeceras de tabla
            String[] cabeceras = {"Vulnerabilidad", "Línea", "Descripción"};
            for (String cabecera : cabeceras) {
                PdfPCell cell = new PdfPCell(new Phrase(cabecera, FontFactory.getFont(FontFactory.HELVETICA_BOLD, 12, BaseColor.WHITE)));
                cell.setBackgroundColor(new BaseColor(44, 62, 80)); // Color oscuro estilo tu app (#2C3E50)
                cell.setHorizontalAlignment(Element.ALIGN_CENTER);
                cell.setPadding(8);
                table.addCell(cell);
            }

            // Datos de la tabla
            for (Vulnerabilidad v : p.getVulnerabilidades()) {
                table.addCell(new Phrase(v.getTipoAtaque(), fontNormal));
                
                PdfPCell cellLinea = new PdfPCell(new Phrase(String.valueOf(v.getLineaAfectada()), fontNormal));
                cellLinea.setHorizontalAlignment(Element.ALIGN_CENTER);
                table.addCell(cellLinea);
                
                table.addCell(new Phrase(v.getDescripcion(), fontNormal));
            }
            document.add(table);
        }

        document.close();
    }
}