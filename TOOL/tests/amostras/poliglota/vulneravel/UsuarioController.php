<?php
// Amostra vulneravel: Laravel.
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class UsuarioController extends Controller
{
    private $apiToken = 'tok_live_abcdef123456'; // achado: CWE-798

    public function buscar(Request $request)
    {
        $ordem = $request->input('ordem');
        $usuarios = DB::select("SELECT * FROM usuarios ORDER BY " . $ordem); // achado: CWE-89
        $ativos = User::whereRaw("ativo = 1 AND nome LIKE '%" . $request->query('q') . "%'")->get(); // achado: CWE-89
        return view('usuarios', ['usuarios' => $usuarios]);
    }

    public function sair(Request $request)
    {
        return redirect()->away($request->input('next')); // achado: CWE-601
    }
}
