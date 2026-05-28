package com.tfg.analizador.presentacion;

import java.util.Optional;

import org.fxmisc.flowless.VirtualizedScrollPane;
import org.fxmisc.richtext.CodeArea;
import org.fxmisc.richtext.LineNumberFactory;

import com.tfg.analizador.logica.ServicioAnalisis;
import com.tfg.analizador.modelo.Protocolo;
import com.tfg.analizador.util.GestorDialogos;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.ListView;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.layout.StackPane;

public class ControladorAnalisis {

    @FXML
    private StackPane contenedorEditor;

    @FXML
    private ListView<String> listaActores;

    @FXML
    private TableView<?> tablaVulnerabilidades;

    @FXML
    private TableColumn<?, ?> colVulnNombre;

    @FXML
    private TableColumn<?, ?> colVulnLinea;

    @FXML
    private TableColumn<?, ?> colVulnDesc;

    private CodeArea editorProtocolo;

    @FXML
    public void initialize() {
        // Establecer KDC por defecto
        listaActores.getItems().add("KDC");

        // Instanciamos el editor avanzado
        editorProtocolo = new CodeArea();
        editorProtocolo.setParagraphGraphicFactory(LineNumberFactory.get(editorProtocolo));
        
        // Esto sirve para evitar apelotonamientos
        VirtualizedScrollPane<CodeArea> scrollEditor = new VirtualizedScrollPane<>(editorProtocolo);
        
        // Inyectamos el panel de scroll
        contenedorEditor.getChildren().add(scrollEditor);
    }

    @FXML
    void handleNuevoActor(ActionEvent event) {
        // Abre la ventana de crear nuevo actor
        Optional<String> resultado = GestorDialogos.solicitarNombreActor();
        
        // Si se pulsa añadir tras escribir un nuevo actor
        resultado.ifPresent(nombre -> {
            if (nombre.isEmpty()) {
                GestorDialogos.mostrarConfirmacionEstandar("Advertencia", "Campo vacío", "El nombre del actor no puede estar en blanco.", "Aceptar");
            } else if (listaActores.getItems().contains(nombre)) {
                GestorDialogos.mostrarConfirmacionEstandar("Advertencia", "Actor duplicado", "El actor '" + nombre + "' ya existe en la lista.", "Aceptar");
            } else {
                listaActores.getItems().add(nombre);
            }
        });
    }

    @FXML
    void handleValidarSintaxis(ActionEvent event) {
        // Extraemos el texto plano del editor avanzado
        String textoUsuario = editorProtocolo.getText();

        if (textoUsuario.trim().isEmpty()) {
            GestorDialogos.mostrarConfirmacionEstandar("Aviso", "Editor vacío", "Escribe un protocolo antes de validar.", "Aceptar");
            return;
        }

        try {
            // Delegamos la validación y compilación a la capa de servicios lógicos
            ServicioAnalisis servicio = new ServicioAnalisis();
            Protocolo protocoloProcesado = servicio.procesarNuevoProtocolo(textoUsuario);

            // Actualizamos la interfaz visual
            actualizarListaActores(protocoloProcesado);
            
            GestorDialogos.mostrarConfirmacionEstandar("Éxito", "Sintaxis Correcta", "El protocolo tiene la estructura correcta y los actores han sido cargados.", "Aceptar");
        } catch (Exception e) {
            // Mostramos el mensaje de la excepción
            GestorDialogos.mostrarConfirmacionEstandar("Error", "Problema detectado", e.getMessage(), "Aceptar");
        }
    }

    private void actualizarListaActores(Protocolo protocolo) {
        // KDC es obligatorio, este if se hace que no se duplique
        if (!listaActores.getItems().contains("KDC")) {
            listaActores.getItems().add("KDC"); 
        }
        
        // Los actores del texto se añaden si no existen en la interfaz visual
        for (com.tfg.analizador.modelo.Agente agente : protocolo.getAgentes()) {
            if (!listaActores.getItems().contains(agente.getNombre())) {
                listaActores.getItems().add(agente.getNombre());
            }
        }
    }
}