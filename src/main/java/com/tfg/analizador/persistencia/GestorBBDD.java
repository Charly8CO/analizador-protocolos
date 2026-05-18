package com.tfg.analizador.persistencia;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.List;

import com.tfg.analizador.modelo.Protocolo;
import com.tfg.analizador.modelo.Usuario;

public class GestorBBDD {

    private static Connection conexion = null;
    
    //URL de la base de datos
    private static final String URL = "jdbc:sqlite:analisis.db?foreign_keys=on";

    //establecer conexión y devolverla para que se pueda usar
    public static Connection getConexion() {
        try {
            // si no existe o si se ha cerrado previamente
            if (conexion == null || conexion.isClosed()) {
                conexion = DriverManager.getConnection(URL);
                System.out.println("Se ha establecido conexión con la base de datos");
            }
        } catch (SQLException e) {
            System.err.println("No se ha podido establecer conexión con la base de datos: " + e.getMessage());
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

	/**
	 * 
	 * @param us
	 */
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


	/**
	 * 
	 * @param email
	 */
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
	 * 
	 * @param nombre
	 * @param hashPass
	 */
	public Usuario verificarCredenciales(String nombre, String hashPass) {
		// TODO - implement GestorBBDD.verificarCredenciales
		throw new UnsupportedOperationException();
	}

	/**
	 * 
	 * @param u
	 * @param p
	 */
	public boolean guardarHistorial(Usuario u, Protocolo p) {
		// TODO - implement GestorBBDD.guardarHistorial
		throw new UnsupportedOperationException();
	}

	/**
	 * 
	 * @param idusuario
	 */
	public List<Protocolo> cargarProtocolos(int idusuario) {
		// TODO - implement GestorBBDD.cargarProtocolos
		throw new UnsupportedOperationException();
	}

	/**
	 * 
	 * @param idprotocolo
	 */
	public boolean eliminarProtocolo(int idprotocolo) {
		// TODO - implement GestorBBDD.eliminarProtocolo
		throw new UnsupportedOperationException();
	}

}