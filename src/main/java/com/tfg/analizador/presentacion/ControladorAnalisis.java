package com.tfg.analizador.presentacion;

import java.util.Optional;

import org.fxmisc.flowless.VirtualizedScrollPane;
import org.fxmisc.richtext.CodeArea;
import org.fxmisc.richtext.LineNumberFactory;

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
}