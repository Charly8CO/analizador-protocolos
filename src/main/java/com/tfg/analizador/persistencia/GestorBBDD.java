package com.tfg.analizador.persistencia;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.List;

import com.tfg.analizador.modelo.Protocolo;
import com.tfg.analizador.modelo.Usuario;

public class GestorBBDD {

    private static Connection conexion = null;
    
    //URL de la base de datos
    private static final String URL = "jdbc:sqlite:analisis.db?foreign_keys=on";

    // Establecer conexión y devolverla para que se pueda usar
   	public static Connection getConexion() throws SQLException {
        if (conexion == null || conexion.isClosed()) {
            conexion = DriverManager.getConnection(URL);
            System.out.println("Se ha establecido conexión con la base de datos");
        }
        return conexion;
    }

    public static void cerrarConexion() {
        try {
            if (conexion != null && !conexion.isClosed()) {
                conexion.close();
                System.out.println("Conexión con la base de datos cerrada.");
            }
        } catch (SQLException e) {
            System.err.println("Se ha producido un error al cerrar la conexión: " + e.getMessage());
        }
    }

	public static void inicializarTablas() {
		// tabla USUARIO
		String sqlUsuario = "CREATE TABLE IF NOT EXISTS USUARIO ("
				+ "id_usuario INTEGER PRIMARY KEY AUTOINCREMENT, "
				+ "nombre_usuario TEXT UNIQUE NOT NULL, "
				+ "hash_contra TEXT NOT NULL"
				+ ");";

		//Tabla PROTOCOLO
		String sqlProtocolo = "CREATE TABLE IF NOT EXISTS PROTOCOLO ("
				+ "id_protocolo INTEGER PRIMARY KEY AUTOINCREMENT, "
				+ "id_usuario INTEGER NOT NULL, "
				+ "nombre_protocolo TEXT NOT NULL, "
				+ "fecha_analisis TEXT, "
				+ "es_seguro INTEGER, "
				+ "Path TEXT NOT NULL, "
				+ "FOREIGN KEY (id_usuario) REFERENCES USUARIO(id_usuario) ON DELETE CASCADE"
				+ ");";

		// Tabla VULNERABILIDAD
		String sqlVulnerabilidad = "CREATE TABLE IF NOT EXISTS VULNERABILIDAD ("
				+ "id_vulnerabilidad INTEGER PRIMARY KEY AUTOINCREMENT, "
				+ "id_protocolo INTEGER NOT NULL, "
				+ "nombre_vulnerabilidad TEXT NOT NULL, "
				+ "tipo_vulnerabilidad TEXT NOT NULL, "
				+ "linea INTEGER NOT NULL, "
				+ "descripcion TEXT, "
				+ "FOREIGN KEY (id_protocolo) REFERENCES PROTOCOLO(id_protocolo) ON DELETE CASCADE"
				+ ");";

		try (java.sql.Statement stmt = getConexion().createStatement()) {
			stmt.execute(sqlUsuario);
			stmt.execute(sqlProtocolo);
			stmt.execute(sqlVulnerabilidad);
			System.out.println("Base de datos inicializada: Estructura de tablas comprobada.");
		} catch (SQLException e) {
			System.err.println("Error crítico al inicializar las tablas: " + e.getMessage());
		}
	}

	public void guardarUsuario(Usuario us) throws SQLException{
		// Los ? ? sirven para indicar que los datos necesarios para la consulta serán enviados luego
		// Evita ataques de inyección
		String sql = "INSERT INTO USUARIO (nombre_usuario, hash_contra) VALUES (?, ?)";
		
		// Abrimos el canal de la consulta 
		// Al hacerlo con el try hacemos que se cierre al terminar		
		try (java.sql.PreparedStatement stmt = getConexion().prepareStatement(sql)) {
			// Pasamos los datos reales en vez de las  1 = primer ? y 2 = segundo ?
			stmt.setString(1, us.getNombreUsuario());
			stmt.setString(2, us.getHashPass());
			//actualizamos
			stmt.executeUpdate();
			System.out.println("Usuario guardado con éxito");
		}
	}

	public Usuario obtenerUsuarioEmail(String email) throws SQLException{
		String sql = "SELECT * FROM USUARIO WHERE nombre_usuario = ?";
		try(java.sql.PreparedStatement stmt = getConexion().prepareStatement(sql)){
			stmt.setString(1, email);
			try(java.sql.ResultSet rs = stmt.executeQuery()){
				if (rs.next()) {
					Usuario u = new Usuario();
					u.setIdUsuario(rs.getInt("id_usuario"));
					u.setNombreUsuario(rs.getString("nombre_usuario"));
					u.setHashPass(rs.getString("hash_contra"));
					return u;
				}
			}
		}
		//Cuando el usuario no existe
		return null;
	}

	/**
	 * Inserta el registro de un archivo de protocolo en la base de datos.
	 * Se usa CURRENT_TIMESTAMP para la fecha automática. es_seguro queda en NULL.
	 */
	public static boolean insertarProtocolo(int idUsuario, String nombreArchivo, String rutaAbsoluta) {
        String sql = "INSERT INTO PROTOCOLO (id_usuario, nombre_protocolo, Path, fecha_analisis) VALUES (?, ?, ?, CURRENT_TIMESTAMP)";

        try (Connection conn = getConexion(); 
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setInt(1, idUsuario);
            pstmt.setString(2, nombreArchivo);
            pstmt.setString(3, rutaAbsoluta);
            
            pstmt.executeUpdate();
            return true;
            
        } catch (SQLException e) {
            System.err.println("Error al insertar el protocolo en SQLite: " + e.getMessage());
            return false;
        }
    }

	public Usuario verificarCredenciales(String nombre, String hashPass) {
		throw new UnsupportedOperationException();
	}

	public boolean guardarHistorial(Usuario u, Protocolo p) {
		throw new UnsupportedOperationException();
	}

	public List<Protocolo> cargarProtocolos(int idusuario) {
		throw new UnsupportedOperationException();
	}

	public boolean eliminarProtocolo(int idprotocolo) {
		throw new UnsupportedOperationException();
	}
}