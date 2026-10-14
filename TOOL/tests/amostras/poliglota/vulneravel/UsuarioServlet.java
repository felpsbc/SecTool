// Amostra vulneravel: Servlet com JDBC.
import java.io.*;
import java.sql.*;
import javax.servlet.http.*;
import javax.xml.parsers.*;

public class UsuarioServlet extends HttpServlet {
    private static final String DB_PASSWORD = "Pr0ducao!2024"; // achado: CWE-798

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String id = request.getParameter("id");
        Connection conn = DriverManager.getConnection("jdbc:mysql://db/app", "app", "root123"); // achado: CWE-798
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM usuarios WHERE id = '" + id + "'"); // achado: CWE-89

        String nome = request.getParameter("nome");
        response.getWriter().println("<h1>Ola " + nome + "</h1>"); // achado: CWE-79

        PrintWriter out = response.getWriter();
        StringBuilder html = new StringBuilder();
        html.append("<p>");
        html.append(request.getParameter("bio"));
        out.print(html.toString()); // achado: CWE-79

        String arquivo = request.getParameter("arquivo");
        FileInputStream entrada = new FileInputStream(new File("/srv/uploads", arquivo)); // achado: CWE-22

        response.sendRedirect(request.getParameter("next")); // achado: CWE-601
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance(); // achado: CWE-611
        factory.newDocumentBuilder().parse(request.getInputStream());

        Cookie sessao = new Cookie("sessao", "abc"); // achado: CWE-614, CWE-1004
        response.addCookie(sessao);
    }
}
