// Amostra vulneravel: Spring MVC + JPA + Spring Security.
import org.springframework.web.bind.annotation.*;

@RestController
public class ProdutoController {
    private final JdbcTemplate jdbcTemplate;
    private final EntityManager em;

    @GetMapping("/produtos")
    public List<Map<String, Object>> buscar(@RequestParam String ordem) {
        return jdbcTemplate.queryForList("SELECT * FROM produtos ORDER BY " + ordem); // achado: CWE-89
    }

    @GetMapping("/produto/{nome}")
    public Produto porNome(@PathVariable String nome) {
        String jpql = "SELECT p FROM Produto p WHERE p.nome = '" + nome + "'";
        return em.createQuery(jpql, Produto.class).getSingleResult(); // achado: CWE-89
    }

    @GetMapping("/saudacao")
    public String saudacao(String visitante) {
        return "<h1>Bem-vindo, " + visitante + "</h1>"; // achado: CWE-79
    }

    @GetMapping("/anexo")
    public byte[] anexo(@RequestParam String caminho) throws Exception {
        return Files.readAllBytes(Paths.get("/srv/anexos", caminho)); // achado: CWE-22
    }
}

@Configuration
class Seguranca {
    @Bean
    SecurityFilterChain filtros(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable); // achado: CWE-352
        return http.build();
    }
}

@Controller
class LoginController {
    @PostMapping("/login")
    public String entrar(@RequestParam String next) {
        return "redirect:" + next; // limitacao: CWE-601 prefixo redirect: do Spring nao e modelado como sink
    }
}
