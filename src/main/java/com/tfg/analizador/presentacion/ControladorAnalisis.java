package com.tfg.analizador.presentacion;

import java.io.File;
import java.util.Optional;

import org.fxmisc.flowless.VirtualizedScrollPane;
import org.fxmisc.richtext.CodeArea;
import org.fxmisc.richtext.LineNumberFactory;

import com.tfg.analizador.logica.ServicioAnalisis;
import com.tfg.analizador.modelo.Protocolo;
import com.tfg.analizador.modelo.Vulnerabilidad;
import com.tfg.analizador.util.GestorDialogos;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.ListView;
import javafx.scene.control.TableCell;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.cell.PropertyValueFactory; 
import javafx.scene.layout.StackPane;
import javafx.scene.text.Text;
import javafx.stage.FileChooser;

public class ControladorAnalisis {

    @FXML
    private StackPane contenedorEditor;

    @FXML
    private ListView<String> listaActores;

    @FXML
    private TableView<Vulnerabilidad> tablaVulnerabilidades;

    @FXML
    private TableColumn<Vulnerabilidad, String> colVulnNombre;

    @FXML
    private TableColumn<Vulnerabilidad, Integer> colVulnLinea;

    @FXML
    private TableColumn<Vulnerabilidad, String> colVulnDesc;

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

        colVulnNombre.setCellValueFactory(new PropertyValueFactory<>("tipoAtaque"));
        colVulnLinea.setCellValueFactory(new PropertyValueFactory<>("lineaAfectada"));
        colVulnDesc.setCellValueFactory(new PropertyValueFactory<>("descripcion"));

        // Envolvemos el texto de la descripción para que salte de línea automáticamente
        colVulnDesc.setCellFactory(tc -> {
            TableCell<Vulnerabilidad, String> cell = new TableCell<>() {
                private Text text = new Text();
                @Override
                protected void updateItem(String item, boolean empty) {
                    super.updateItem(item, empty);
                    if (empty || item == null) {
                        setGraphic(null);
                    } else {
                        text.setText(item);
                        // Restamos unos píxeles de padding para que no se pegue al borde
                        text.wrappingWidthProperty().bind(colVulnDesc.widthProperty().subtract(10));
                        setGraphic(text);
                    }
                }
            };
            return cell;
        });

        colVulnNombre.setCellFactory(tc -> {
            TableCell<Vulnerabilidad, String> cell = new TableCell<>() {
                private Text text = new Text();
                @Override
                protected void updateItem(String item, boolean empty) {
                    super.updateItem(item, empty);
                    if (empty || item == null) {
                        setGraphic(null);
                    } else {
                        text.setText(item);
                        // Restamos unos píxeles de padding para que no se pegue al borde
                        text.wrappingWidthProperty().bind(colVulnNombre.widthProperty().subtract(10));
                        setGraphic(text);
                    }
                }
            };
            return cell;
        });
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

    // Ahora este botón solo valida la sintaxis léxica.No hace cálculos criptográficos ni rellena la tabla.
    @FXML
    void handleValidarSintaxis(ActionEvent event) {
        String textoUsuario = editorProtocolo.getText();

        if (textoUsuario.trim().isEmpty()) {
            GestorDialogos.mostrarConfirmacionEstandar("Aviso", "Editor vacío", "Escribe un protocolo antes de validar.", "Aceptar");
            return;
        }

        try {
            ServicioAnalisis servicio = new ServicioAnalisis();
            servicio.validarSintaxisSolo(textoUsuario); // Lanza excepción si la estructura falla

            GestorDialogos.mostrarConfirmacionEstandar("Validación", "Sintaxis Correcta", "La estructura del protocolo es válida. Puedes proceder a analizarlo.", "Aceptar");
        } catch (Exception e) {
            GestorDialogos.mostrarConfirmacionEstandar("Error de Sintaxis", "Estructura incorrecta", e.getMessage(), "Aceptar");
        }
    }

    // Este botón ejecuta tanto el validador léxico como el motor de 
    // seguridad, volcando los resultados finales en la interfaz.
    @FXML
    void handleAnalizarProtocolo(ActionEvent event) {
        String textoUsuario = editorProtocolo.getText();

        if (textoUsuario.trim().isEmpty()) {
            GestorDialogos.mostrarConfirmacionEstandar("Aviso", "Editor vacío", "Escribe un protocolo antes de analizar.", "Aceptar");
            return;
        }

        try {
            // Delegamos la validación y compilación a la capa de servicios lógicos
            ServicioAnalisis servicio = new ServicioAnalisis();
            Protocolo protocoloProcesado = servicio.procesarNuevoProtocolo(textoUsuario);

            // Actualizamos la interfaz visual
            actualizarListaActores(protocoloProcesado);
            
            // Volcamos la lista de vulnerabilidades a un formato observable que JavaFX entiende
            ObservableList<Vulnerabilidad> data = FXCollections.observableArrayList(protocoloProcesado.getVulnerabilidades());

            // Al inyectar la data ahora, las columnas (gracias al PropertyValueFactory) sabrán qué mostrar
            tablaVulnerabilidades.setItems(data);

            // Mantenemos el feedback visual intacto
            if (protocoloProcesado.isSeguro()) {
                GestorDialogos.mostrarConfirmacionEstandar("Análisis Finalizado", "Protocolo Seguro", "No se han detectado fallos lógicos. El diseño es robusto.", "Aceptar");
            } else {
                GestorDialogos.mostrarConfirmacionEstandar(
                    "Análisis Finalizado", 
                    "Vulnerabilidades Detectadas", 
                    "El motor ha encontrado " + protocoloProcesado.getVulnerabilidades().size() + " brechas de seguridad. Revisa la tabla lateral para más detalles.", 
                    "Aceptar");
            }
        } catch (Exception e) {
            // Mostramos el mensaje de la excepción (errores léxicos o sintácticos que paren la compilación)
            GestorDialogos.mostrarConfirmacionEstandar("Error de Compilación", "No se puede analizar", e.getMessage(), "Aceptar");
        }
    }

    @FXML
    void handleGuardarProtocolo(ActionEvent event) {
        String texto = editorProtocolo.getText();

        if (texto.trim().isEmpty()) {
            GestorDialogos.mostrarConfirmacionEstandar("Aviso", "Editor vacío", "No hay contenido para guardar.", "Aceptar");
            return;
        }

        // Configuramos el selector de archivos
        FileChooser selector = new FileChooser();
        selector.setTitle("Guardar Protocolo");
        selector.getExtensionFilters().add(new FileChooser.ExtensionFilter("Archivos de Protocolo (*.prot)", "*.prot"));
        
        // Abrimos la ventana de guardado
        File archivo = selector.showSaveDialog(contenedorEditor.getScene().getWindow());

        if (archivo != null) {
            try {
                ServicioAnalisis servicio = new ServicioAnalisis();
                // Delegamos el guardado físico y en BBDD
                servicio.guardarProtocolo(archivo, texto);
                
                GestorDialogos.mostrarConfirmacionEstandar("Éxito", "Protocolo Guardado", "El archivo se ha guardado correctamente en: " + archivo.getName(), "Aceptar");
            } catch (Exception e) {
                GestorDialogos.mostrarConfirmacionEstandar("Error", "Error al guardar", e.getMessage(), "Aceptar");
            }
        }
    }

    @FXML
    void handleLimpiarProtocolo(ActionEvent event) {
        boolean confirmar = GestorDialogos.mostrarConfirmacionEstandar(
            "Confirmar limpieza", 
            "¿Vaciar editor?", 
            "Se borrará todo el texto actual. ¿Deseas continuar?", 
            "Limpiar"
        );
        
        if (confirmar) {
            editorProtocolo.clear();
            listaActores.getItems().clear();
            listaActores.getItems().add("KDC"); // Mantenemos el KDC por defecto
            tablaVulnerabilidades.getItems().clear();
        }
    }

    private void actualizarListaActores(Protocolo protocolo) {
        // KDC es obligatorio, este if hace que no se duplique
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