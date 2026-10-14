// Amostra segura: mesmos fluxos com a defesa correta.
import org.owasp.encoder.Encode;

@RestController
public class ContaController {
    private final JdbcTemplate jdbcTemplate;

    @GetMapping("/conta")
    public Map<String, Object> conta(@RequestParam String id) {
        return jdbcTemplate.queryForMap("SELECT * FROM contas WHERE id = ?", id);
    }

    @GetMapping("/pagina")
    public List<Map<String, Object>> pagina(@RequestParam String pagina) {
        int numero = Integer.parseInt(pagina);
        return jdbcTemplate.queryForList("SELECT * FROM contas LIMIT 10 OFFSET " + numero * 10);
    }

    @GetMapping("/saudacao")
    public String saudacao(String visitante) {
        return "<h1>Bem-vindo, " + Encode.forHtml(visitante) + "</h1>";
    }

    @GetMapping("/anexo")
    public byte[] anexo(@RequestParam String caminho) throws Exception {
        return Files.readAllBytes(Paths.get("/srv/anexos", FilenameUtils.getName(caminho)));
    }

    void conectar(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String senha = System.getenv("DB_PASSWORD");
        Connection conn = DriverManager.getConnection("jdbc:mysql://db/app", "app", senha);
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM u WHERE id = ?");
        ps.setString(1, request.getParameter("id"));

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

        Cookie sessao = new Cookie("sessao", "abc");
        sessao.setSecure(true);
        sessao.setHttpOnly(true);
        response.addCookie(sessao);
        response.sendRedirect("/inicio");
    }
}
