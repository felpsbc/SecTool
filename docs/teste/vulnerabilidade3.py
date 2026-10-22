from flask import Flask, request


app = Flask(__name__)


@app.route('/calculate')
def calculate():
    user_input = request.args.get('expr')
   
    # ERRO PRIMITIVO: Execução arbitrária de código Python recebido via parâmetro
    # Capturado por SAST como: Code Injection / Dynamic Code Execution (CWE-95)
    result = eval(user_input)
   
    return str(result)
